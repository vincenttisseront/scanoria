// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API de la console dans le processus de test, contre un vrai PostgreSQL 16 :
// le greffon de démarrage (migrations embarquées, premier administrateur),
// le contrôle commun (origine, session, CSRF, mot de passe imposé) et chaque
// point d'accès de server/api sont servis par h3 sur 127.0.0.1, comme Nitro.

import { readdirSync } from 'node:fs'
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, unlink, writeFile } from 'node:fs/promises'
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
import { setBuildInfo } from '../../server/utils/appliance'

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
      NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
      NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
      NUXT_DNS_STATUS_FILE: join(root, 'dns-status.json'),
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
  describe('catalogue des modules', () => {
    const FIXTURES = fileURLToPath(new URL('../fixtures/', import.meta.url))
    let viewer: Client
    // Fichier de la demande renvoyée par l'API (plusieurs demandes peuvent partager la même seconde).
    const incomingFor = async (res: { data: Record<string, unknown> }, type: string) => {
      const dir = join(root, 'requests', 'incoming')
      const docs = await Promise.all((await readdir(dir)).map(async n => JSON.parse(await readFile(join(dir, n), 'utf8')) as { id: string, type: string, params: Record<string, unknown> }))
      return docs.find(d => d.id === res.data.request_id && d.type === type)
    }

    beforeAll(async () => {
      // Les modules du catalogue exigent une appliance >= 0.2.0.
      setBuildInfo({ version: '0.2.0', sourceRepo: 'exemple/scanoria' })
      await writeFile(join(root, 'state.json'), JSON.stringify({
        version: 1, generated_at: new Date().toISOString(),
        appliance: { fqdn: 'analyse.exemple.test', version: '0.2.0', cpu_count: 4, memory_mb: 8192 },
        helper: { busy: false, current: null, queue_length: 0 },
        disks: [{ mount: '/', size_mb: 40960, avail_mb: 20000 }],
      }))
      viewer = await newUser('catalogue-lecteur', 'viewer')
    })
    afterAll(() => setBuildInfo({ version: '0.1.0', sourceRepo: 'exemple/scanoria' }))

    it('sans index : vue vide, plan et installation refusés (503)', async () => {
      const res = await call('/api/catalog', { client: viewer })
      expect(res.status).toBe(200)
      expect(res.data.index).toMatchObject({ available: false })
      expect(res.data.recommended).toMatchObject({ ids: [], first_access: true })
      expect(code(await call('/api/catalog/plan', { method: 'POST', client: viewer, json: { pack: 'base' } }))).toBe('E_CATALOG_UNAVAILABLE')
      expect(code(await call('/api/catalog/install', { method: 'POST', client: admin, json: { pack: 'base' } }))).toBe('E_CATALOG_UNAVAILABLE')
      expect((await call('/api/catalog/modules/gitleaks', { client: viewer })).status).toBe(404)
      const dns = await call('/api/dns', { client: viewer })
      expect(dns.data).toEqual({ fqdn: 'analyse.exemple.test', status: null, required: [] })
      for (const f of ['catalog-index.json', 'modules-state.json', 'dns-status.json']) await copyFile(join(FIXTURES, f), join(root, f))
    })

    it('vue complète pour un lecteur', async () => {
      const res = await call('/api/catalog', { client: viewer })
      const modules = res.data.modules as { id: string, update_available: string | null, installed: unknown }[]
      expect(modules.find(m => m.id === 'gitleaks')).toMatchObject({ update_available: '8.28.0' })
      expect(res.data.machine).toMatchObject({ cpu_count: 4, memory_mb: 8192 })
      expect((res.data.operations as unknown[]).length).toBe(2)
      expect(JSON.stringify(res.data)).not.toContain('sha256')
      const detail = await call('/api/catalog/modules/trivy', { client: viewer })
      expect(detail.data).toMatchObject({ versions: ['0.67.2', '0.66.0'], update_available: '0.67.2', dependents: [] })
      expect((await call('/api/catalog/modules/ancien', { client: viewer })).data).toMatchObject({ module: null, plan: null })
      expect((await call('/api/catalog/modules/BAD', { client: viewer })).status).toBe(404)
      expect((await call('/api/catalog/modules/inconnu', { client: viewer })).status).toBe(404)
    })

    it('plan : dépendances, licences ; validation des corps', async () => {
      const plan = await call('/api/catalog/plan', { method: 'POST', client: viewer, json: { modules: [{ id: 'osv-scanner' }, { id: 'codeql' }] } })
      expect(plan.status).toBe(200)
      expect((plan.data.items as { id: string }[]).map(i => i.id)).toEqual(['osv-scanner', 'codeql', 'osv-db'])
      expect(plan.data.licenses_to_accept).toEqual(['codeql'])
      for (const json of [{}, { pack: 'base', modules: [{ id: 'gitleaks' }] }, { modules: [] }, { pack: '../x' }]) {
        expect(code(await call('/api/catalog/plan', { method: 'POST', client: viewer, json })), JSON.stringify(json)).toBe('E_VALIDATION')
      }
      expect(code(await call('/api/catalog/plan', { method: 'POST', client: viewer, json: { pack: 'inconnu' } }))).toBe('E_NOT_FOUND')
      expect(code(await call('/api/catalog/plan', { method: 'POST', client: viewer, json: { pack: 'base' } }))).toBe('E_PLAN')
    })

    it('installation : admin seulement, plan bloqué refusé, demande avec défauts et licences', async () => {
      const json = { modules: [{ id: 'osv-scanner' }, { id: 'codeql' }] }
      expect(code(await call('/api/catalog/install', { method: 'POST', client: viewer, json }))).toBe('E_FORBIDDEN')
      const blocked = await call('/api/catalog/install', { method: 'POST', client: admin, json })
      expect(blocked.status).toBe(409)
      expect(blocked.data.data).toMatchObject({ code: 'E_PLAN', blockers: [{ code: 'E_LICENSE_REQUIRED', other: 'codeql' }] })
      const ok = await call('/api/catalog/install', { method: 'POST', client: admin, json: { ...json, accept_licenses: ['codeql'] } })
      expect(ok.status, JSON.stringify(ok.data)).toBe(202)
      expect((await incomingFor(ok, 'install-modules'))!.params).toEqual({
        modules: [
          { id: 'osv-scanner', version: '2.2.0', options: {} },
          { id: 'codeql', version: '2.23.0', options: {} },
          { id: 'osv-db', version: '1', options: {} },
        ],
        accept_licenses: ['codeql'],
      })
      const audit = await call('/api/audit?action=system.install-modules.request', { client: admin })
      expect(JSON.stringify(audit.data)).toContain('osv-db')
      const pack = await call('/api/catalog/install', { method: 'POST', client: admin, json: { pack: 'secrets' } })
      expect(pack.data.data).toMatchObject({ code: 'E_PLAN', blockers: [{ code: 'W_PACK_INSTALLED', other: 'secrets' }] })
      const iac = await call('/api/catalog/install', { method: 'POST', client: admin, json: { pack: 'iac' } })
      expect(iac.data.data).toMatchObject({ code: 'E_PLAN', blockers: [{ code: 'E_NOT_FOUND', module: 'checkov' }] })
    })

    it('activation, mise à jour, désinstallation', async () => {
      expect(code(await call('/api/catalog/modules/osv-scanner/state', { method: 'POST', client: admin, json: { enabled: true } }))).toBe('E_NOT_INSTALLED')
      expect(code(await call('/api/catalog/modules/trivy/state', { method: 'POST', client: viewer, json: { enabled: true } }))).toBe('E_FORBIDDEN')
      const enable = await call('/api/catalog/modules/trivy/state', { method: 'POST', client: admin, json: { enabled: true } })
      expect(enable.status).toBe(202)
      expect((await incomingFor(enable, 'set-module-state'))!.params).toEqual({ id: 'trivy', enabled: true })

      const updGitleaks = await call('/api/catalog/modules/gitleaks/update', { method: 'POST', client: admin, json: {} })
      expect(updGitleaks.status).toBe(202)
      expect((await incomingFor(updGitleaks, 'update-module'))!.params).toEqual({ id: 'gitleaks', version: '8.28.0' })
      expect(code(await call('/api/catalog/modules/trivy/update', { method: 'POST', client: admin, json: { version: '0.66.0' } }))).toBe('E_NO_UPDATE')
      expect(code(await call('/api/catalog/modules/trivy/update', { method: 'POST', client: admin, json: { version: '9.9.9' } }))).toBe('E_NOT_FOUND')
      const updTrivy = await call('/api/catalog/modules/trivy/update', { method: 'POST', client: admin, json: {} })
      expect(updTrivy.status).toBe(202)
      expect((await incomingFor(updTrivy, 'update-module'))!.params).toEqual({ id: 'trivy', version: '0.67.2' })
      // Version cible soumise aux mêmes contrôles qu'une installation : licence, dépendances.
      const idx = JSON.parse(await readFile(join(root, 'catalog-index.json'), 'utf8')) as { modules: Record<string, unknown>[] }
      const next = { ...idx.modules.find(m => m.id === 'gitleaks')!, version: '9.0.0', license: { spdx: 'X', restrictions: 'other' }, requires: { modules: [], feeds: ['osv-db'] } }
      await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ ...idx, modules: [...idx.modules, next] }))
      const blocked9 = await call('/api/catalog/modules/gitleaks/update', { method: 'POST', client: admin, json: { version: '9.0.0' } })
      expect(blocked9.data.data).toMatchObject({ code: 'E_PLAN', blockers: [{ code: 'E_LICENSE_REQUIRED' }, { code: 'E_DEPENDENCY', other: 'osv-db' }] })
      await writeFile(join(root, 'catalog-index.json'), JSON.stringify(idx))

      const blocked = await call('/api/catalog/modules/trivy-db/uninstall', { method: 'POST', client: admin, json: { keep_data: true } })
      expect(blocked.data.data).toMatchObject({ code: 'E_DEPENDENTS', dependents: ['trivy'] })
      expect(code(await call('/api/catalog/modules/gitleaks/uninstall', { method: 'POST', client: admin, json: {} }))).toBe('E_VALIDATION')
      const uninstall = await call('/api/catalog/modules/gitleaks/uninstall', { method: 'POST', client: admin, json: { keep_data: false } })
      expect(uninstall.status).toBe(202)
      expect((await incomingFor(uninstall, 'uninstall-module'))!.params).toEqual({ id: 'gitleaks', keep_data: false })
      expect((await call('/api/catalog/modules/BAD/uninstall', { method: 'POST', client: admin, json: { keep_data: false } })).status).toBe(404)
    })

    it('actualisation du catalogue et DNS', async () => {
      expect((await call('/api/catalog/refresh', { method: 'POST', client: admin, json: {} })).status).toBe(202)
      expect(code(await call('/api/catalog/refresh', { method: 'POST', client: admin, json: { force: true } }))).toBe('E_VALIDATION')
      expect((await call('/api/catalog/feeds/refresh', { method: 'POST', client: admin, json: {} })).status).toBe(202)
      expect((await call('/api/catalog/feeds/refresh', { method: 'POST', client: admin, json: { ids: ['trivy-db'] } })).status).toBe(202)
      expect(code(await call('/api/catalog/feeds/refresh', { method: 'POST', client: admin, json: { ids: [] } }))).toBe('E_VALIDATION')
      expect(code(await call('/api/catalog/feeds/refresh', { method: 'POST', client: viewer, json: {} }))).toBe('E_FORBIDDEN')
      expect((await call('/api/catalog/modules/trivy-db', { client: viewer })).data.feed).toMatchObject({ id: 'trivy-db', status: 'ok' })
      expect(code(await call('/api/dns/check', { method: 'POST', client: viewer, json: {} }))).toBe('E_FORBIDDEN')
      expect(code(await call('/api/dns/check', { method: 'POST', client: viewer, json: { x: 1 } }))).toBe('E_FORBIDDEN')
      expect((await call('/api/dns/check', { method: 'POST', client: admin, json: {} })).status).toBe(202)
      const dns = await call('/api/dns', { client: viewer })
      expect(dns.data.required).toEqual([
        { name: 'analyse.exemple.test', type: 'A', value: '192.0.2.10' },
        { name: '*.analyse.exemple.test', type: 'A', value: '192.0.2.10' },
        { name: 'analyse.exemple.test', type: 'AAAA', value: '2001:db8::10' },
        { name: '*.analyse.exemple.test', type: 'AAAA', value: '2001:db8::10' },
      ])
    })

    it('suivi : étape et avancement d’une opération de module', async () => {
      const res = await call('/api/catalog/refresh', { method: 'POST', client: admin, json: {} })
      const id = String(res.data.request_id)
      const state = JSON.parse(await readFile(join(root, 'modules-state.json'), 'utf8')) as { operations: Record<string, unknown>[] }
      state.operations[0]!.request_id = id
      await writeFile(join(root, 'modules-state.json'), JSON.stringify(state))
      expect((await call(`/api/requests/${id}`, { client: admin })).data).toMatchObject({ step: 'pull', progress: 40 })
      await unlink(join(root, 'modules-state.json'))
      expect((await call(`/api/requests/${id}`, { client: admin })).data).toMatchObject({ progress: null })
    })
  })
})
