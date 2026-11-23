// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API de la console dans le processus de test, contre un vrai PostgreSQL 16 :
// le greffon de démarrage (migrations embarquées, premier administrateur),
// le contrôle commun (origine, session, CSRF, mot de passe imposé) et chaque
// point d'accès de server/api sont servis par h3 sur 127.0.0.1, comme Nitro.

import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { DATABASE_URL, MIGRATIONS_DIR, createTestDatabase, type TestDatabase } from '../helpers/db'
import { hashPassword } from '../../server/utils/password'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { waitReady, ingestNow } from '../../server/utils/runtime'
import { SESSION_COOKIE } from '../../server/utils/sessions'
import { createUser } from '../../server/utils/users'

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))
// Chemins calculés : le greffon de démarrage utilise les globales de Nitro,
// hors du périmètre de types des tests.
const STARTUP_PLUGIN = fileURLToPath(new URL('../../server/plugins/startup.ts', import.meta.url))
const ADMIN_PASSWORD = 'api-admin-password'

/** Fichiers de server/api → routes h3 (« [id] » → « :id », « index » → racine). */
function apiRoutes(): { method: string, path: string, file: string }[] {
  const out: { method: string, path: string, file: string }[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      const m = /^(.+)\.(get|post|put|patch|delete)\.ts$/.exec(entry.name)
      if (!m) continue
      const segments = relative(API_DIR, dir).split(sep).filter(Boolean)
      if (m[1] !== 'index') segments.push(m[1]!)
      out.push({
        method: m[2]!,
        path: `/api/${segments.map(s => s.replace(/^\[(.+)\]$/, ':$1')).join('/')}`.replace(/\/$/, ''),
        file: full,
      })
    }
  }
  walk(API_DIR)
  return out
}

interface Client {
  cookie: string
  csrf: string
}

describe.skipIf(!DATABASE_URL)('API de la console (h3 dans le processus, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let closeHook: (() => Promise<void>) | undefined
  let ipCounter = 10
  let admin: Client

  const nextIp = () => `198.51.100.${ipCounter++}`

  async function call(path: string, init: RequestInit & { client?: Client, json?: unknown, ip?: string } = {}) {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET' && !headers.has('x-csrf-token')) headers.set('x-csrf-token', init.client.csrf)
    }
    headers.set('x-real-ip', init.ip ?? '192.0.2.10')
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
    return { status: res.status, headers: res.headers, data: data as Record<string, unknown> & { data?: { code?: string, issues?: unknown[] } } }
  }

  async function login(username: string, password: string, ip = nextIp()): Promise<Client> {
    const res = await call('/api/auth/login', { method: 'POST', json: { username, password }, ip })
    expect(res.status, JSON.stringify(res.data)).toBe(200)
    const cookie = (res.headers.get('set-cookie') ?? '').split(';')[0]!
    expect(cookie.startsWith(`${SESSION_COOKIE}=`)).toBe(true)
    return { cookie, csrf: String(res.data.csrf) }
  }

  async function newUser(username: string, role: 'viewer' | 'operator' | 'admin', mustChange = false): Promise<Client> {
    await createUser(db.pool, { username, role, password: `${username}-long-password`, mustChangePassword: mustChange })
    return login(username, `${username}-long-password`)
  }

  const code = (res: { data: { data?: { code?: string } } }) => res.data.data?.code

  beforeAll(async () => {
    db = await createTestDatabase({ migrate: false })
    root = await mkdtemp(join(tmpdir(), 'scanoria-api-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'uploads', 'bootstrap', 'public']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    await writeFile(join(root, 'bootstrap', 'admin.json'), JSON.stringify({ username: 'admin', password_hash: await hashPassword(ADMIN_PASSWORD) }), { mode: 0o600 })
    await writeFile(join(root, 'update-source.json'), JSON.stringify({ repo: 'exemple/scanoria' }))
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_UPLOADS_DIR: join(root, 'uploads'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_PUBLIC_FILES_DIR: join(root, 'public'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_UPDATE_SOURCE_FILE: join(root, 'update-source.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))

    // Greffon de démarrage Nitro : globales de Nitro simulées, migrations
    // servies comme les serverAssets « migrations ».
    vi.stubGlobal('defineNitroPlugin', (fn: unknown) => fn)
    vi.stubGlobal('useRuntimeConfig', () => ({ buildVersion: '0.1.0', buildSourceRepo: 'exemple/scanoria' }))
    vi.stubGlobal('useStorage', () => ({
      getKeys: async () => (await readdir(MIGRATIONS_DIR)).map(n => `assets:migrations:${n}`),
      getItemRaw: async (key: string) => readFile(join(MIGRATIONS_DIR, key.split(':').pop()!)),
    }))
    const plugin = (await import(STARTUP_PLUGIN)).default as unknown as (app: unknown) => void
    plugin({
      hooks: {
        hook: (_name: string, fn: () => Promise<void>) => {
          closeHook = fn
        },
      },
    })
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const r of apiRoutes()) {
      const handler = (await import(r.file)).default as EventHandler
      router[r.method as 'get'](r.path, handler)
    }
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
    admin = await login('admin', ADMIN_PASSWORD)
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    if (closeHook) await closeHook()
    else await closePool()
    vi.unstubAllGlobals()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  describe('public', () => {
    it('santé, à propos et OpenAPI sans session', async () => {
      const health = await call('/api/health')
      expect(health.status).toBe(200)
      expect(health.data).toEqual({ status: 'ok', version: '0.1.0', db: 'ok' })
      expect(health.headers.get('cache-control')).toBe('no-store')

      const about = await call('/api/about')
      expect(about.data).toMatchObject({
        version: '0.1.0', license: 'AGPL-3.0-or-later',
        source_url: 'https://github.com/exemple/scanoria/tree/v0.1.0',
        repository_url: 'https://github.com/exemple/scanoria',
      })

      const spec = await call('/api/openapi.json')
      expect(spec.status).toBe(200)
      const paths = spec.data.paths as Record<string, Record<string, { security?: unknown[], requestBody?: unknown }>>
      for (const r of apiRoutes()) {
        const p = r.path.replace(/:(\w+)/g, '{$1}')
        expect(paths[p]?.[r.method], `${r.method} ${p}`).toBeTruthy()
      }
      expect(paths['/api/health']!.get!.security).toEqual([])
      expect(paths['/api/users']!.post!.requestBody).toBeTruthy()
    })

    it('session absente : authenticated false ; autres routes 401', async () => {
      expect((await call('/api/auth/session')).data).toEqual({ authenticated: false })
      const state = await call('/api/state')
      expect(state.status).toBe(401)
      expect(code(state)).toBe('E_UNAUTHENTICATED')
    })
  })

  describe('connexion et contrôle commun', () => {
    it('identifiants faux : 401 identique et audité ; corps invalide : 400 sans valeurs', async () => {
      const bad = await call('/api/auth/login', { method: 'POST', json: { username: 'Admin', password: 'faux' }, ip: nextIp() })
      expect(bad.status).toBe(401)
      expect(code(bad)).toBe('E_INVALID_CREDENTIALS')
      const unknown = await call('/api/auth/login', { method: 'POST', json: { username: 'personne', password: 'faux' }, ip: nextIp() })
      expect(code(unknown)).toBe('E_INVALID_CREDENTIALS')
      const invalid = await call('/api/auth/login', { method: 'POST', json: { username: 'admin', password: 'x', extra: 1 }, ip: nextIp() })
      expect(invalid.status).toBe(400)
      expect(JSON.stringify(invalid.data)).not.toContain('"x"')
      const notJson = await call('/api/auth/login', { method: 'POST', body: '{', headers: { 'content-type': 'application/json' }, ip: nextIp() })
      expect(notJson.status).toBe(400)
      const audit = await call('/api/audit?action=auth.login&outcome=failure', { client: admin })
      expect((audit.data.total as number)).toBeGreaterThanOrEqual(2)
    })

    it('limitation par adresse : 429 avec retry-after', async () => {
      const ip = nextIp()
      let last
      for (let i = 0; i < 21; i++) last = await call('/api/auth/login', { method: 'POST', json: { username: 'personne', password: 'faux' }, ip })
      expect(last!.status).toBe(429)
      expect(Number(last!.headers.get('retry-after'))).toBeGreaterThan(0)
    })

    it('origine étrangère et CSRF absent refusés ; session et déconnexion', async () => {
      const c = await login('admin', ADMIN_PASSWORD)
      const session = await call('/api/auth/session', { client: c, ip: '192.0.2.99' })
      expect(session.data).toMatchObject({ authenticated: true, csrf: c.csrf, address: '192.0.2.99', user: { username: 'admin', role: 'admin' } })
      const foreign = await call('/api/auth/logout', { method: 'POST', client: c, headers: { origin: 'https://autre.exemple.test' } })
      expect(code(foreign)).toBe('E_ORIGIN')
      const badOrigin = await call('/api/auth/logout', { method: 'POST', client: c, headers: { origin: 'pas une url' } })
      expect(code(badOrigin)).toBe('E_ORIGIN')
      const site = await call('/api/auth/logout', { method: 'POST', client: c, headers: { 'sec-fetch-site': 'cross-site' } })
      expect(code(site)).toBe('E_ORIGIN')
      const noCsrf = await call('/api/auth/logout', { method: 'POST', client: c, headers: { 'x-csrf-token': 'faux' } })
      expect(code(noCsrf)).toBe('E_CSRF')
      const out = await call('/api/auth/logout', { method: 'POST', client: c, headers: { 'sec-fetch-site': 'same-origin' } })
      expect(out.status).toBe(200)
      expect(out.headers.get('set-cookie')).toContain(`${SESSION_COOKIE}=;`)
      expect((await call('/api/state', { client: c })).status).toBe(401)
    })

    it('nouvelle connexion avec une session existante : l’ancienne est révoquée', async () => {
      const first = await login('admin', ADMIN_PASSWORD)
      const res = await call('/api/auth/login', { method: 'POST', client: first, json: { username: 'admin', password: ADMIN_PASSWORD }, ip: nextIp() })
      expect(res.status).toBe(200)
      expect((await call('/api/auth/session', { client: first })).data).toEqual({ authenticated: false })
    })

    it('changement de mot de passe imposé : seules les routes du compte restent ouvertes', async () => {
      const c = await newUser('forced', 'viewer', true)
      expect(code(await call('/api/state', { client: c }))).toBe('E_PASSWORD_CHANGE_REQUIRED')
      expect((await call('/api/about', { client: c })).status).toBe(200)
      const wrong = await call('/api/auth/password', { method: 'POST', client: c, json: { current_password: 'pas-le-bon-mot', new_password: 'nouveau-mot-de-passe' } })
      expect(code(wrong)).toBe('E_CURRENT_PASSWORD')
      const same = await call('/api/auth/password', { method: 'POST', client: c, json: { current_password: 'forced-long-password', new_password: 'forced-long-password' } })
      expect(code(same)).toBe('E_VALIDATION')
      const ok = await call('/api/auth/password', { method: 'POST', client: c, json: { current_password: 'forced-long-password', new_password: 'nouveau-mot-de-passe' } })
      expect(ok.data).toEqual({ ok: true })
      expect((await call('/api/state', { client: c })).status).toBe(200)
    })
  })

  describe('compte, état, fichiers publics', () => {
    it('préférences du compte', async () => {
      const c = await newUser('prefs', 'viewer')
      const res = await call('/api/account', { method: 'PATCH', client: c, json: { locale: 'en', display_name: 'Préférences' } })
      expect(res.data).toEqual({ locale: 'en', display_name: 'Préférences' })
      expect(((await call('/api/auth/session', { client: c })).data.user as { locale: string }).locale).toBe('en')
    })

    it('état publié : absent, illisible, valide', async () => {
      expect((await call('/api/state', { client: admin })).data).toMatchObject({ available: false, reason: 'missing', console_version: '0.1.0' })
      await writeFile(join(root, 'state.json'), '{')
      expect((await call('/api/state', { client: admin })).data).toMatchObject({ reason: 'invalid' })
      await writeFile(join(root, 'state.json'), JSON.stringify({ version: 1, generated_at: new Date().toISOString(), helper: { current: null } }))
      expect((await call('/api/state', { client: admin })).data).toMatchObject({ available: true })
    })

    it('certificat de l’AC : 404 tant qu’absent ou invalide, puis téléchargé', async () => {
      expect((await call('/api/system/tls/ca', { client: admin })).status).toBe(404)
      await writeFile(join(root, 'public', 'scanoria-ca.crt'), 'pas un certificat')
      expect((await call('/api/system/tls/ca', { client: admin })).status).toBe(404)
      await writeFile(join(root, 'public', 'scanoria-ca.crt'), '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n')
      const res = await call('/api/system/tls/ca', { client: admin })
      expect(res.status).toBe(200)
      expect(res.headers.get('content-disposition')).toContain('scanoria-ca.crt')
    })

    it('historique des mises à jour', async () => {
      await db.pool.query(
        `INSERT INTO update_history (action, from_version, to_version, channel, source, status, code, initiated_by, started_at)
         VALUES ('apply', '0.0.9', '0.1.0', 'stable', 'github', 'success', 'OK', (SELECT id FROM users WHERE username = 'admin'), now())`,
      )
      const res = await call('/api/system/updates/history', { client: admin })
      expect((res.data.items as { to_version: string }[])[0]!.to_version).toBe('0.1.0')
    })
  })

  describe('utilisateurs (administrateur)', () => {
    it('rôles : un lecteur ne liste pas les utilisateurs, un opérateur lit l’audit', async () => {
      const viewer = await newUser('lecteur', 'viewer')
      expect(code(await call('/api/users', { client: viewer }))).toBe('E_FORBIDDEN')
      expect(code(await call('/api/audit', { client: viewer }))).toBe('E_FORBIDDEN')
      const op = await newUser('operateur', 'operator')
      const audit = await call('/api/audit?limit=5', { client: op })
      expect(audit.status).toBe(200)
      const first = (audit.data.items as { id: string }[])[0]!
      expect((await call(`/api/audit/${first.id}`, { client: op })).data).toMatchObject({ id: first.id })
      expect((await call('/api/audit/999999999', { client: op })).status).toBe(404)
      expect((await call('/api/audit/abc', { client: op })).status).toBe(404)
      expect((await call('/api/audit?limit=0', { client: op })).status).toBe(400)
      expect((await call('/api/requests', { client: op })).status).toBe(200)
    })

    it('création, doublon, modification, mot de passe, suppression', async () => {
      const created = await call('/api/users', {
        method: 'POST', client: admin,
        json: { username: 'carol', display_name: 'Carol', email: 'carol@exemple.test', role: 'viewer', locale: 'en', password: 'carol-initial-password' },
      })
      expect(created.status).toBe(201)
      const id = String(created.data.id)
      const dup = await call('/api/users', { method: 'POST', client: admin, json: { username: 'carol', role: 'viewer', password: 'carol-initial-password' } })
      expect(code(dup)).toBe('E_USERNAME_TAKEN')
      const list = await call('/api/users', { client: admin })
      expect((list.data.items as { username: string }[]).map(u => u.username)).toContain('carol')

      const patched = await call(`/api/users/${id}`, { method: 'PATCH', client: admin, json: { role: 'operator', display_name: null } })
      expect(patched.data).toMatchObject({ role: 'operator', display_name: null })
      expect((await call('/api/users/424242', { method: 'PATCH', client: admin, json: { role: 'viewer' } })).status).toBe(404)

      const reset = await call(`/api/users/${id}/password`, { method: 'POST', client: admin, json: { password: 'carol-reset-password', must_change_password: false } })
      expect(reset.data).toEqual({ ok: true })
      await login('carol', 'carol-reset-password')
      expect((await call('/api/users/424242/password', { method: 'POST', client: admin, json: { password: 'carol-reset-password' } })).status).toBe(404)

      expect((await call(`/api/users/${id}`, { method: 'DELETE', client: admin })).data).toEqual({ ok: true })
      expect((await call(`/api/users/${id}`, { method: 'DELETE', client: admin })).status).toBe(404)
      const audit = await call('/api/audit?action=user.', { client: admin })
      expect((audit.data.items as { action: string }[]).map(a => a.action)).toEqual(expect.arrayContaining(['user.create', 'user.update', 'user.password-reset', 'user.delete']))
    })

    it('garde-fous : soi-même, dernier administrateur', async () => {
      const me = ((await call('/api/auth/session', { client: admin })).data.user as { id: number }).id
      expect(code(await call(`/api/users/${me}`, { method: 'DELETE', client: admin }))).toBe('E_SELF')
      expect(code(await call(`/api/users/${me}`, { method: 'PATCH', client: admin, json: { role: 'viewer' } }))).toBe('E_LAST_ADMIN')
      const other = await call('/api/users', { method: 'POST', client: admin, json: { username: 'second', role: 'admin', password: 'second-admin-password' } })
      expect(code(await call(`/api/users/${me}`, { method: 'PATCH', client: admin, json: { is_active: false } }))).toBe('E_SELF')
      await call(`/api/users/${String(other.data.id)}`, { method: 'PATCH', client: admin, json: { is_active: false } })
      // le seul autre administrateur est inactif : la suppression du dernier actif est refusée
      const sole = await newUser('seul', 'admin')
      await call(`/api/users/${me}`, { method: 'PATCH', client: sole, json: { role: 'operator' } })
      expect(code(await call(`/api/users/${((await call('/api/auth/session', { client: sole })).data.user as { id: number }).id}`, { method: 'PATCH', client: sole, json: { role: 'viewer' } }))).toBe('E_LAST_ADMIN')
      // rétablit l'administrateur principal
      await call(`/api/users/${me}`, { method: 'PATCH', client: sole, json: { role: 'admin' } })
      admin = await login('admin', ADMIN_PASSWORD)
      expect((await call('/api/users', { client: admin })).status).toBe(200)
    })
  })

  describe('demandes au service root', () => {
    async function incoming(): Promise<Record<string, unknown>[]> {
      const dir = join(root, 'requests', 'incoming')
      return Promise.all((await readdir(dir)).map(async n => JSON.parse(await readFile(join(dir, n), 'utf8')) as Record<string, unknown>))
    }

    it('chaque action dépose une demande validée (202) et l’audite ; un lecteur est refusé', async () => {
      const posts: [string, unknown][] = [
        ['/api/system/hostname', { fqdn: 'analyse.exemple.test' }],
        ['/api/system/admin-networks', { networks: ['192.0.2.0/24'] }],
        ['/api/system/selftest', { quick: true }],
        ['/api/system/tls/issue', { force: true }],
        ['/api/system/tls/import', { cert_pem: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n', key_pem: '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n' }],
        ['/api/system/updates/check', {}],
        ['/api/system/updates/policy', { channel: 'stable', auto_check: true, auto_apply: false, maintenance_window: null }],
        ['/api/system/updates/rollback', { expected_current: '0.1.0', expected_target: '0.0.9' }],
        ['/api/system/updates/apply', { source: 'github', version: '0.2.0' }],
      ]
      for (const [path, json] of posts) {
        const res = await call(path, { method: 'POST', client: admin, json })
        expect(res.status, `${path} ${JSON.stringify(res.data)}`).toBe(202)
        expect(res.data.status).toBe('pending')
      }
      const files = await incoming()
      expect(files.map(f => f.type).sort()).toEqual([
        'apply-update', 'check-update', 'import-certificate', 'issue-certificate', 'rollback-update',
        'run-selftest', 'set-admin-networks', 'set-hostname', 'set-update-policy',
      ])
      // la clé privée n'est jamais recopiée dans le journal d'audit
      const audit = await call('/api/audit?action=system.import-certificate', { client: admin })
      expect(JSON.stringify(audit.data)).not.toContain('PRIVATE KEY')

      const viewer = await newUser('lecteur2', 'viewer')
      expect(code(await call('/api/system/selftest', { method: 'POST', client: viewer, json: {} }))).toBe('E_FORBIDDEN')
      expect(code(await call('/api/system/hostname', { method: 'POST', client: admin, json: { fqdn: 'pas un nom' } }))).toBe('E_VALIDATION')
    })

    it('suivi d’une demande : étape publiée, résultat ingéré, droits du lecteur', async () => {
      const res = await call('/api/system/selftest', { method: 'POST', client: admin, json: {} })
      const id = String(res.data.request_id)
      await writeFile(join(root, 'state.json'), JSON.stringify({
        version: 1, generated_at: new Date().toISOString(), helper: { busy: true, current: { id, type: 'run-selftest', step: 'run' } },
      }))
      const pending = await call(`/api/requests/${id}`, { client: admin })
      expect(pending.data).toMatchObject({ id, step: 'run' })
      const op = await newUser('suivi', 'operator')
      expect((await call(`/api/requests/${id}`, { client: op })).status).toBe(200)
      const viewer = await newUser('curieux', 'viewer')
      expect(code(await call(`/api/requests/${id}`, { client: viewer }))).toBe('E_FORBIDDEN')
      expect((await call('/api/requests/pas-un-uuid', { client: admin })).status).toBe(404)
      expect((await call('/api/requests/0f8fad5b-d9cb-469f-a165-70867728950e', { client: admin })).status).toBe(404)
      await ingestNow()
    })

    it('téléversement hors ligne : noms admis, tailles bornées, installation depuis le dépôt complet', async () => {
      const start = await call('/api/system/updates/uploads', { method: 'POST', client: admin })
      expect(start.status).toBe(201)
      const id = String(start.data.upload_id)
      const put = (name: string, body: string | Blob) => call(`/api/system/updates/uploads/${id}/${encodeURIComponent(name)}`, {
        method: 'PUT', client: admin, body, headers: { 'content-type': 'application/octet-stream' },
      })
      // installation refusée tant que les fichiers manquent
      expect(code(await call('/api/system/updates/apply', { method: 'POST', client: admin, json: { source: 'upload', upload_id: id } }))).toBe('E_UPLOAD')
      expect(code(await put('autre.txt', 'x'))).toBe('E_UPLOAD')
      expect(code(await put('SHA256SUMS.sig', 'x'.repeat(65)))).toBe('E_TOO_LARGE')
      expect((await call(`/api/system/updates/uploads/0f8fad5b-d9cb-469f-a165-70867728950e/release.json`, { method: 'PUT', client: admin, body: '{}' })).status).toBe(404)
      expect((await call(`/api/system/updates/uploads/pas-un-uuid/release.json`, { method: 'PUT', client: admin, body: '{}' })).status).toBe(404)
      for (const [name, body] of [['release.json', '{}'], ['SHA256SUMS', 'abc'], ['SHA256SUMS.sig', 'sig']] as const) {
        const res = await put(name, body)
        expect(res.status).toBe(201)
        expect(res.data).toEqual({ upload_id: id, name, size: body.length })
      }
      expect(code(await put('release.json', '{}'))).toBe('E_UPLOAD')
      expect(code(await call('/api/system/updates/apply', { method: 'POST', client: admin, json: { source: 'upload', upload_id: id } }))).toBe('E_UPLOAD')
      expect((await put('scanoria-0.2.0.tar.zst', new Blob([new Uint8Array([1, 2, 3])]))).status).toBe(201)
      const apply = await call('/api/system/updates/apply', { method: 'POST', client: admin, json: { source: 'upload', upload_id: id } })
      expect(apply.status).toBe(202)
    })
  })
})
