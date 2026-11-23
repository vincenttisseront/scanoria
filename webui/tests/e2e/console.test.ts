// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Bout en bout : serveur construit (.output/server/index.mjs) lancé sur
// 127.0.0.1 contre une base PostgreSQL 16 jetable (DATABASE_URL), appels HTTP
// réels. Prérequis : `npm run build`.

import { type ChildProcess, spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { hashPassword } from '../../server/utils/password'

const SERVER = fileURLToPath(new URL('../../.output/server/index.mjs', import.meta.url))
const ADMIN_PASSWORD = 'e2e-admin-password'

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer()
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      srv.close(() => (typeof addr === 'object' && addr ? resolve(addr.port) : reject(new Error('no port'))))
    })
  })
}

interface Client {
  cookie: string
  csrf: string
}

describe.skipIf(!DATABASE_URL || !existsSync(SERVER))('console de bout en bout', () => {
  let db: TestDatabase
  let root: string
  let server: ChildProcess
  let base: string
  let logs = ''

  async function call(path: string, init: RequestInit & { client?: Client, json?: unknown } = {}) {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    let body = init.body
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    const res = await fetch(`${base}${path}`, { ...init, headers, body })
    const text = await res.text()
    let data: unknown = text
    try {
      data = JSON.parse(text)
    }
    catch {
      // texte brut
    }
    return { status: res.status, headers: res.headers, data: data as Record<string, unknown> & { data?: { code?: string } } }
  }

  async function login(username: string, password: string): Promise<Client> {
    const res = await call('/api/auth/login', { method: 'POST', json: { username, password }, headers: { 'x-real-ip': '192.0.2.10' } })
    expect(res.status, JSON.stringify(res.data)).toBe(200)
    const setCookie = res.headers.get('set-cookie') ?? ''
    const cookie = setCookie.split(';')[0]!
    return { cookie, csrf: String(res.data.csrf) }
  }

  beforeAll(async () => {
    db = await createTestDatabase({ migrate: false })
    root = await mkdtemp(join(tmpdir(), 'scanoria-e2e-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'uploads', 'bootstrap', 'public']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    await writeFile(join(root, 'bootstrap', 'admin.json'), JSON.stringify({ username: 'admin', password_hash: await hashPassword(ADMIN_PASSWORD) }), { mode: 0o600 })
    await writeFile(join(root, 'public', 'scanoria-ca.crt'), '-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n')
    await writeFile(join(root, 'update-source.json'), JSON.stringify({ repo: 'exemple/scanoria' }))
    const port = await freePort()
    base = `http://127.0.0.1:${port}`
    server = spawn(process.execPath, [SERVER], {
      env: {
        ...process.env,
        NITRO_HOST: '127.0.0.1',
        NITRO_PORT: String(port),
        NUXT_DATABASE_URL: db.url,
        NUXT_REQUESTS_DIR: join(root, 'requests'),
        NUXT_UPLOADS_DIR: join(root, 'uploads'),
        NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
        NUXT_PUBLIC_FILES_DIR: join(root, 'public'),
        NUXT_STATE_FILE: join(root, 'state.json'),
        NUXT_UPDATE_SOURCE_FILE: join(root, 'update-source.json'),
        NUXT_VERSION_FILE: join(root, 'VERSION'),
        NUXT_INGEST_INTERVAL_MS: '500',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    server.stdout?.on('data', (d) => {
      logs += d
    })
    server.stderr?.on('data', (d) => {
      logs += d
    })
    const deadline = Date.now() + 60_000
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${base}/api/health`)
        if (res.status === 200) return
      }
      catch {
        // pas encore prêt
      }
      await new Promise(r => setTimeout(r, 300))
    }
    throw new Error(`server did not start:\n${logs}`)
  })

  afterAll(async () => {
    server?.kill('SIGTERM')
    await new Promise(r => setTimeout(r, 500))
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('répond sur /api/health sans authentification, sans autre information', async () => {
    const res = await call('/api/health')
    expect(res.status).toBe(200)
    expect(res.data).toEqual({ status: 'ok', version: '0.1.0', db: 'ok' })
  })

  it('sert l’application et la page À propos avec le lien vers le tag installé', async () => {
    const page = await fetch(`${base}/login`)
    expect(page.status).toBe(200)
    expect(page.headers.get('x-frame-options')).toBe('DENY')
    const about = await call('/api/about')
    expect(about.data).toMatchObject({ license: 'AGPL-3.0-or-later', source_url: 'https://github.com/exemple/scanoria/tree/v0.1.0' })
    const openapi = await call('/api/openapi.json')
    expect(openapi.data.openapi).toBe('3.1.0')
    expect(Object.keys(openapi.data.paths as object)).toContain('/api/system/updates/apply')
  })

  it('exige une session pour le reste de l’API', async () => {
    const res = await call('/api/state')
    expect(res.status).toBe(401)
    expect(res.data.data?.code).toBe('E_UNAUTHENTICATED')
  })

  it('refuse un mauvais mot de passe et audite l’échec', async () => {
    const res = await call('/api/auth/login', { method: 'POST', json: { username: 'admin', password: 'wrong-password' } })
    expect(res.status).toBe(401)
    expect(res.data.data?.code).toBe('E_INVALID_CREDENTIALS')
    const hostile = await call('/api/auth/login', { method: 'POST', json: { username: 'admin', password: 'x', role: 'admin' } })
    expect(hostile.status).toBe(400)
  })

  it('pose un cookie de session httpOnly, Secure, SameSite=Strict', async () => {
    const res = await call('/api/auth/login', { method: 'POST', json: { username: 'admin', password: ADMIN_PASSWORD } })
    const cookie = res.headers.get('set-cookie') ?? ''
    expect(cookie).toMatch(/^__Host-scanoria_session=[A-Za-z0-9_-]{43};/)
    expect(cookie).toMatch(/HttpOnly/i)
    expect(cookie).toMatch(/Secure/i)
    expect(cookie).toMatch(/SameSite=Strict/i)
    expect(cookie).toMatch(/Path=\//)
  })

  it('protège contre la falsification de requête (CSRF, origine)', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const noCsrf = await call('/api/system/selftest', { method: 'POST', json: {}, headers: { cookie: admin.cookie } })
    expect(noCsrf.status).toBe(403)
    expect(noCsrf.data.data?.code).toBe('E_CSRF')
    const crossSite = await call('/api/system/selftest', { method: 'POST', json: {}, client: admin, headers: { 'sec-fetch-site': 'cross-site' } })
    expect(crossSite.data.data?.code).toBe('E_ORIGIN')
    const badOrigin = await call('/api/system/selftest', { method: 'POST', json: {}, client: admin, headers: { origin: 'https://attaquant.exemple.test' } })
    expect(badOrigin.data.data?.code).toBe('E_ORIGIN')
  })

  it('applique les rôles côté serveur et impose le changement du mot de passe initial', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const created = await call('/api/users', { method: 'POST', client: admin, json: { username: 'olivia', role: 'operator', password: 'initial-password-1' } })
    expect(created.status).toBe(201)
    const dup = await call('/api/users', { method: 'POST', client: admin, json: { username: 'olivia', role: 'viewer', password: 'initial-password-1' } })
    expect(dup.data.data?.code).toBe('E_USERNAME_TAKEN')

    const operator = await login('olivia', 'initial-password-1')
    const blocked = await call('/api/state', { client: operator })
    expect(blocked.data.data?.code).toBe('E_PASSWORD_CHANGE_REQUIRED')
    const changed = await call('/api/auth/password', { method: 'POST', client: operator, json: { current_password: 'initial-password-1', new_password: 'olivia-new-password' } })
    expect(changed.status).toBe(200)

    expect((await call('/api/state', { client: operator })).status).toBe(200)
    expect((await call('/api/audit', { client: operator })).status).toBe(200)
    const users = await call('/api/users', { client: operator })
    expect(users.status).toBe(403)
    expect(users.data.data?.code).toBe('E_FORBIDDEN')
    const helper = await call('/api/system/hostname', { method: 'POST', client: operator, json: { fqdn: 'analyse.exemple.test' } })
    expect(helper.status).toBe(403)
  })

  it('protège le dernier administrateur et son propre compte', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const list = await call('/api/users', { client: admin })
    const me = (list.data.items as { id: string, username: string }[]).find(u => u.username === 'admin')!
    const demote = await call(`/api/users/${me.id}`, { method: 'PATCH', client: admin, json: { role: 'viewer' } })
    expect(demote.data.data?.code).toBe('E_LAST_ADMIN')
    const del = await call(`/api/users/${me.id}`, { method: 'DELETE', client: admin })
    expect(del.data.data?.code).toBe('E_SELF')
  })

  it('dépose une demande conforme au contrat puis suit son résultat', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const bad = await call('/api/system/hostname', { method: 'POST', client: admin, json: { fqdn: 'x;reboot' } })
    expect(bad.status).toBe(400)
    expect(bad.data.data?.code).toBe('E_VALIDATION')

    const res = await call('/api/system/hostname', { method: 'POST', client: admin, json: { fqdn: 'analyse.exemple.test' }, headers: { 'x-real-ip': '198.51.100.20' } })
    expect(res.status).toBe(202)
    const id = String(res.data.request_id)
    const incoming = await readdir(join(root, 'requests', 'incoming'))
    const name = incoming.find(n => n.endsWith(`-${id}.json`))!
    expect(name).toMatch(/^[0-9]{8}T[0-9]{6}Z-[0-9a-f-]{36}\.json$/)
    const envelope = JSON.parse(await readFile(join(root, 'requests', 'incoming', name), 'utf8'))
    expect(envelope).toMatchObject({
      version: 1, id, type: 'set-hostname',
      requested_by: { username: 'admin', address: '198.51.100.20' },
      params: { fqdn: 'analyse.exemple.test' },
    })

    const pending = await call(`/api/requests/${id}`, { client: admin })
    expect(pending.data.status).toBe('pending')

    await rm(join(root, 'requests', 'incoming', name))
    await writeFile(join(root, 'requests', 'done', name), JSON.stringify({
      version: 1, id, type: 'set-hostname', origin: 'console', status: 'ok', code: 'OK', message: 'hostname set',
      received_at: envelope.created_at, started_at: envelope.created_at, finished_at: envelope.created_at,
      output: { fqdn: 'analyse.exemple.test', tls_mode_changed: false },
    }))
    const done = await call(`/api/requests/${id}`, { client: admin })
    expect(done.data).toMatchObject({ status: 'ok', code: 'OK' })

    const audit = await call('/api/audit?action=system.set-hostname', { client: admin })
    const actions = (audit.data.items as { action: string }[]).map(i => i.action).sort()
    expect(actions).toEqual(['system.set-hostname.request', 'system.set-hostname.result'])
  })

  it('lit l’état publié et le déclare périmé au-delà de 3 minutes', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const state = (generated: Date) => JSON.stringify({ version: 1, generated_at: `${generated.toISOString().slice(0, 19)}Z`, helper: { busy: false, current: null, queue_length: 0 } })
    await writeFile(join(root, 'state.json'), state(new Date()))
    expect((await call('/api/state', { client: admin })).data.available).toBe(true)
    await writeFile(join(root, 'state.json'), state(new Date(Date.now() - 5 * 60_000)))
    expect((await call('/api/state', { client: admin })).data).toMatchObject({ available: false, reason: 'stale' })
  })

  it('reçoit un téléversement hors ligne borné puis dépose apply-update', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const started = await call('/api/system/updates/uploads', { method: 'POST', client: admin })
    expect(started.status).toBe(201)
    const uploadId = String(started.data.upload_id)
    const put = (name: string, body: string | Uint8Array<ArrayBuffer>) => call(`/api/system/updates/uploads/${uploadId}/${encodeURIComponent(name)}`, {
      method: 'PUT', client: admin, body, headers: { 'content-type': 'application/octet-stream' },
    })
    expect((await put('../../etc/passwd', 'x')).status).toBeGreaterThanOrEqual(400)
    expect((await put('SHA256SUMS.sig', new Uint8Array(65))).status).toBe(413)
    const early = await call('/api/system/updates/apply', { method: 'POST', client: admin, json: { source: 'upload', upload_id: uploadId } })
    expect(early.data.data?.code).toBe('E_UPLOAD')
    expect((await put('release.json', '{}')).status).toBe(201)
    expect((await put('SHA256SUMS', 'x')).status).toBe(201)
    expect((await put('SHA256SUMS.sig', new Uint8Array(64))).status).toBe(201)
    expect((await put('scanoria-0.2.0.tar.zst', new Uint8Array(1024))).status).toBe(201)
    expect((await put('release.json', '{}')).status).toBe(400)
    const apply = await call('/api/system/updates/apply', { method: 'POST', client: admin, json: { source: 'upload', upload_id: uploadId } })
    expect(apply.status).toBe(202)
    expect((await readdir(join(root, 'uploads', uploadId))).sort()).toEqual(['SHA256SUMS', 'SHA256SUMS.sig', 'release.json', 'scanoria-0.2.0.tar.zst'])
  })

  it('télécharge le certificat de l’AC et ferme la session à la déconnexion', async () => {
    const admin = await login('admin', ADMIN_PASSWORD)
    const ca = await fetch(`${base}/api/system/tls/ca`, { headers: { cookie: admin.cookie } })
    expect(ca.status).toBe(200)
    expect(await ca.text()).toContain('BEGIN CERTIFICATE')
    expect((await call('/api/auth/logout', { method: 'POST', client: admin })).status).toBe(200)
    expect((await call('/api/state', { client: admin })).status).toBe(401)
  })
})
