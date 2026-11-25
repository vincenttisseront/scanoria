// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Hors ligne (0.6, chantier A) contre un vrai PostgreSQL 16 : droits, entrées
// hostiles, demandes déposées au service root, téléversement en flux,
// téléchargement d'un lot exporté, et reflet des résultats du helper dans
// trusted_keys et offline_bundles.

import { createHash, randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { IngestMemory, ingestResults } from '../../server/utils/ingest'
import { keyFingerprint, readOfflineStatus } from '../../server/offline/status'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>
interface Client { cookie: string, csrf: string }

const API = '../../server/api/system/offline'
const ROUTES: [method: 'get' | 'post' | 'put', path: string, file: string][] = [
  ['post', '/api/auth/login', '../../server/api/auth/login.post.ts'],
  ['get', '/api/audit', '../../server/api/audit/index.get.ts'],
  ['get', '/api/system/offline', `${API}/index.get.ts`],
  ['post', '/api/system/offline/keys', `${API}/keys/index.post.ts`],
  ['post', '/api/system/offline/keys/remove', `${API}/keys/remove.post.ts`],
  ['post', '/api/system/offline/export', `${API}/export.post.ts`],
  ['post', '/api/system/offline/schedule', `${API}/schedule.post.ts`],
  ['post', '/api/system/offline/uploads', `${API}/uploads/index.post.ts`],
  ['put', '/api/system/offline/uploads/:id', `${API}/uploads/[id].put.ts`],
  ['post', '/api/system/offline/import', `${API}/import.post.ts`],
  ['post', '/api/system/offline/mirror', `${API}/mirror.post.ts`],
  ['get', '/api/system/offline/bundles/:name', `${API}/bundles/[name].get.ts`],
]

// Clé publique et empreinte calculées à l'exécution : aucune valeur fixe dans le dépôt.
const PUB = randomBytes(32).toString('base64')
const FPR = createHash('sha256').update(Buffer.from(PUB, 'base64')).digest('hex')
const OTHER_FPR = createHash('sha256').update(randomBytes(32)).digest('hex')
const BUNDLE = 'scanoria-bundle-20261124T020000Z.tar'

describe.skipIf(!DATABASE_URL)('bundle : API hors ligne (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let operator: Client
  let viewer: Client
  let ip = 10
  const memory = new IngestMemory()

  async function call(path: string, init: { method?: string, client?: Client, json?: unknown, body?: Buffer | string } = {}) {
    const headers = new Headers({ 'x-real-ip': `198.51.100.${ip++ % 250}` })
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    let body: BodyInit | undefined
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    else if (init.body !== undefined) {
      headers.set('content-type', 'application/octet-stream')
      body = init.body as BodyInit
    }
    const res = await fetch(`${base}${path}`, { method: init.method, headers, body })
    const text = await res.text()
    let data: Json
    try {
      data = JSON.parse(text) as Json
    }
    catch {
      data = { raw: text }
    }
    return { status: res.status, data, headers: res.headers, text }
  }
  const code = (res: { data: Json }) => res.data?.data?.code as string | undefined
  const post = (path: string, client: Client, json: unknown = {}) => call(path, { method: 'POST', client, json })

  async function login(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client> {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const res = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++ % 250}` },
      body: JSON.stringify({ username, password }),
    })
    expect(res.status).toBe(200)
    const data = await res.json() as Json
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
  }

  async function incoming(requestId: unknown) {
    const dir = join(root, 'requests', 'incoming')
    for (const n of await readdir(dir)) {
      const doc = JSON.parse(await readFile(join(dir, n), 'utf8')) as Json
      if (doc.id === requestId) return { name: n, doc }
    }
    return undefined
  }

  /** Simule le helper : écrit le résultat d'une demande puis l'ingère. */
  async function complete(requestId: string, ok: boolean, output: Json, codeName = ok ? 'OK' : 'E_BUNDLE_SIGNATURE') {
    const req = await incoming(requestId)
    expect(req).toBeDefined()
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
    const result = {
      // Identifiant relu du fichier de demande déposé, jamais celui de la réponse HTTP.
      version: 1, id: req!.doc.id, type: req!.doc.type, origin: 'console', status: ok ? 'ok' : 'error', code: codeName,
      message: ok ? 'done' : 'invalid bundle signature', received_at: now, started_at: now, finished_at: now, output,
    }
    await writeFile(join(root, 'requests', ok ? 'done' : 'failed', req!.name), JSON.stringify(result))
    await ingestResults(db.pool, join(root, 'requests'), memory)
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-bundle-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap', 'uploads', 'bundles', 'offline']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_UPLOADS_DIR: join(root, 'uploads'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
      NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
      NUXT_DNS_STATUS_FILE: join(root, 'dns-status.json'),
      NUXT_OFFLINE_STATUS_FILE: join(root, 'offline', 'status.json'),
      NUXT_BUNDLES_DIR: join(root, 'bundles'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '600000',
    }))
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const [method, path, file] of ROUTES) router[method](path, (await import(file)).default as EventHandler)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
    admin = await login('offline-admin', 'admin')
    operator = await login('offline-operateur', 'operator')
    viewer = await login('offline-lecteur', 'viewer')
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    await stopConsole()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('état : opérateur et plus ; sans état publié, valeurs par défaut sûres', async () => {
    expect(code(await call('/api/system/offline', { client: viewer }))).toBe('E_FORBIDDEN')
    const r = await call('/api/system/offline', { client: operator })
    expect(r.status).toBe(200)
    expect(r.data).toMatchObject({ available: false, appliance_key: null, trusted_keys: [], exports: [], mirror: null })
    expect(r.data.schedule).toEqual({ enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null })
  })

  it('état publié : lu et validé ; non conforme : ignoré', async () => {
    const status = {
      version: 1, updated_at: '2026-11-24T02:00:00Z', appliance_key: { public_key: PUB, fingerprint: FPR }, trusted_keys: [FPR],
      bundles: [{ name: BUNDLE, created_at: '2026-11-24T02:00:00Z', size_bytes: 12, sha256: FPR, signer_fingerprint: FPR, modules: ['gitleaks'], feeds: [], images: ['gitleaks'], catalog_version: 12, scheduled: false }],
      last_import: null, mirror: null, publication: null,
      schedule: { enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null },
      dtrack: { synced_at: '2026-11-24T02:00:00Z', configured_at: null, configure_error: null, port: 9790, sources: [], gaps: [{ id: 'nvd', reason: 'no-feed' }] },
    }
    const path = join(root, 'offline', 'status.json')
    await writeFile(path, JSON.stringify(status))
    expect((await readOfflineStatus(path))?.appliance_key?.fingerprint).toBe(FPR)
    const r = await call('/api/system/offline', { client: operator })
    expect(r.data).toMatchObject({ available: true, appliance_key: { fingerprint: FPR }, exports: [{ name: BUNDLE }] })
    await writeFile(path, JSON.stringify({ ...status, appliance_key: { public_key: 'x', fingerprint: FPR } }))
    expect(await readOfflineStatus(path)).toBeNull()
    await writeFile(path, '{')
    expect(await readOfflineStatus(path)).toBeNull()
    await writeFile(path, JSON.stringify(status))
  })

  it('empreinte : SHA-256 de la clé brute, base64 canonique seulement', () => {
    expect(keyFingerprint(PUB)).toBe(FPR)
    expect(keyFingerprint('A'.repeat(44))).toBeNull()
    expect(keyFingerprint(`${PUB.slice(0, 42)}B=`)).not.toBe(FPR)
  })

  it('clé de confiance : admin seulement, empreinte confirmée = empreinte de la clé', async () => {
    const url = '/api/system/offline/keys'
    expect(code(await post(url, operator, { label: 'Siège', public_key: PUB, fingerprint: FPR }))).toBe('E_FORBIDDEN')
    for (const json of [
      {}, { label: '', public_key: PUB, fingerprint: FPR }, { label: 'Siège', public_key: 'pas une clé', fingerprint: FPR },
      { label: 'Siège', public_key: PUB, fingerprint: OTHER_FPR }, { label: 'Siège', public_key: PUB, fingerprint: FPR, extra: 1 },
      { label: 'x'.repeat(101), public_key: PUB, fingerprint: FPR },
    ]) {
      expect(code(await post(url, admin, json)), JSON.stringify(json)).toBe('E_VALIDATION')
    }
    const ok = await post(url, admin, { label: 'Appliance du siège', public_key: PUB, fingerprint: FPR })
    expect(ok.status, JSON.stringify(ok.data)).toBe(202)
    const req = await incoming(ok.data.request_id)
    expect(req?.doc).toMatchObject({ type: 'trust-key', params: { action: 'add', public_key: PUB, fingerprint: FPR } })
    expect(req?.doc.params.label).toBeUndefined()
    // Rien en base tant que le helper n'a pas confirmé.
    expect((await db.pool.query('SELECT 1 FROM trusted_keys')).rowCount).toBe(0)
    await complete(ok.data.request_id, true, { action: 'add', fingerprint: FPR, public_key: PUB })
    const rows = await db.pool.query('SELECT label, purpose, revoked_at FROM trusted_keys WHERE fingerprint = $1', [FPR])
    expect(rows.rows).toEqual([{ label: 'Appliance du siège', purpose: 'bundle', revoked_at: null }])
    const view = await call('/api/system/offline', { client: operator })
    expect(view.data.trusted_keys).toEqual([expect.objectContaining({ fingerprint: FPR, in_store: true, added_by_username: 'offline-admin' })])
  })

  it('retrait d’une clé : revoked_at posé au résultat, ligne gardée pour l’audit', async () => {
    expect(code(await post('/api/system/offline/keys/remove', admin, { fingerprint: '../x' }))).toBe('E_VALIDATION')
    expect(code(await post('/api/system/offline/keys/remove', operator, { fingerprint: FPR }))).toBe('E_FORBIDDEN')
    const ok = await post('/api/system/offline/keys/remove', admin, { fingerprint: FPR })
    expect(ok.status).toBe(202)
    expect((await incoming(ok.data.request_id))?.doc.params).toEqual({ action: 'remove', fingerprint: FPR })
    await complete(ok.data.request_id, true, { action: 'remove', fingerprint: FPR, removed: true })
    const rows = await db.pool.query('SELECT revoked_at FROM trusted_keys WHERE fingerprint = $1', [FPR])
    expect(rows.rows[0].revoked_at).not.toBeNull()
    // Ré-ajout : la même ligne redevient active.
    const again = await post('/api/system/offline/keys', admin, { label: 'Siège (bis)', public_key: PUB, fingerprint: FPR })
    await complete(again.data.request_id, true, { action: 'add', fingerprint: FPR, public_key: PUB })
    const back = await db.pool.query('SELECT label, revoked_at FROM trusted_keys WHERE fingerprint = $1', [FPR])
    expect(back.rows).toEqual([{ label: 'Siège (bis)', revoked_at: null }])
  })

  it('un échec du helper n’ajoute aucune clé', async () => {
    const other = randomBytes(32).toString('base64')
    const fp = keyFingerprint(other)!
    const r = await post('/api/system/offline/keys', admin, { label: 'Refusée', public_key: other, fingerprint: fp })
    await complete(r.data.request_id, false, {}, 'E_KEY_INVALID')
    expect((await db.pool.query('SELECT 1 FROM trusted_keys WHERE fingerprint = $1', [fp])).rowCount).toBe(0)
  })

  it('export : estimation sans trace, export tracé de la file jusqu’au résultat', async () => {
    const url = '/api/system/offline/export'
    expect(code(await post(url, operator, { modules: ['gitleaks'] }))).toBe('E_FORBIDDEN')
    for (const json of [{}, { modules: [] }, { modules: ['../etc'] }, { modules: ['gitleaks', 'gitleaks'] }, { schedule: { enabled: true, every_days: 7, keep: 2, modules: ['gitleaks'] } }, { scheduled: true }]) {
      expect(code(await post(url, admin, json)), JSON.stringify(json)).toBe('E_VALIDATION')
    }
    const dry = await post(url, admin, { modules: ['gitleaks'], dry_run: true })
    expect(dry.status).toBe(202)
    expect((await incoming(dry.data.request_id))?.doc.params).toEqual({ modules: ['gitleaks'], dry_run: true })
    await complete(dry.data.request_id, true, { dry_run: true, estimated_bytes: 1024, modules: ['gitleaks'], feeds: [], images: ['gitleaks'] })
    expect((await db.pool.query('SELECT 1 FROM offline_bundles')).rowCount).toBe(0)

    const run = await post(url, admin, { modules: ['gitleaks', 'osv-scanner'] })
    expect(run.status).toBe(202)
    const queued = await db.pool.query('SELECT status, direction, contents FROM offline_bundles WHERE request_id = $1', [run.data.request_id])
    expect(queued.rows).toEqual([{ status: 'queued', direction: 'export', contents: { modules: ['gitleaks', 'osv-scanner'] } }])
    await complete(run.data.request_id, true, {
      dry_run: false, name: BUNDLE, sha256: FPR, size_bytes: 4096, signer_fingerprint: FPR, created_at: '2026-11-24T02:00:00Z',
      modules: ['gitleaks', 'osv-scanner', 'osv-db'], feeds: ['osv-db'], images: ['gitleaks', 'osv-scanner'], testbeds: 2, catalog_version: 12, removed: [],
    })
    const done = await db.pool.query('SELECT status, size_bytes::int AS size, sha256, signer_fingerprint, contents->>\'name\' AS name FROM offline_bundles WHERE request_id = $1', [run.data.request_id])
    expect(done.rows).toEqual([{ status: 'done', size: 4096, sha256: FPR, signer_fingerprint: FPR, name: BUNDLE }])
  })

  it('export périodique : réglage déposé, sans ligne de lot ; export du minuteur tracé', async () => {
    const url = '/api/system/offline/schedule'
    for (const json of [{}, { schedule: { enabled: true, every_days: 0, keep: 2, modules: [] } }, { schedule: { enabled: true, every_days: 7, keep: 2, modules: [], last_run_at: null } }]) {
      expect(code(await post(url, admin, json)), JSON.stringify(json)).toBe('E_VALIDATION')
    }
    const before = (await db.pool.query('SELECT count(*)::int AS n FROM offline_bundles')).rows[0].n
    const r = await post(url, admin, { schedule: { enabled: true, every_days: 7, keep: 3, modules: ['gitleaks'] } })
    expect(r.status).toBe(202)
    expect((await incoming(r.data.request_id))?.doc.params).toEqual({ schedule: { enabled: true, every_days: 7, keep: 3, modules: ['gitleaks'] } })
    await complete(r.data.request_id, true, { schedule: { enabled: true, every_days: 7, keep: 3, modules: ['gitleaks'], last_run_at: null } })
    expect((await db.pool.query('SELECT count(*)::int AS n FROM offline_bundles')).rows[0].n).toBe(before)
  })

  it('téléversement : admin, identifiant valide, flux écrit tel quel ; vide ou rejoué refusé', async () => {
    expect(code(await post('/api/system/offline/uploads', operator))).toBe('E_FORBIDDEN')
    const open = await post('/api/system/offline/uploads', admin)
    expect(open.status).toBe(201)
    const id = open.data.upload_id as string
    expect(code(await call('/api/system/offline/uploads/not-a-uuid', { method: 'PUT', client: admin, body: 'x' }))).toBe('E_NOT_FOUND')
    expect(code(await call('/api/system/offline/uploads/3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f', { method: 'PUT', client: admin, body: 'x' }))).toBe('E_NOT_FOUND')
    expect(code(await call(`/api/system/offline/uploads/${id}`, { method: 'PUT', client: viewer, body: 'x' }))).toBe('E_FORBIDDEN')
    const payload = randomBytes(256 * 1024)
    const put = await call(`/api/system/offline/uploads/${id}`, { method: 'PUT', client: admin, body: payload })
    expect(put.status, JSON.stringify(put.data)).toBe(201)
    expect(put.data.size).toBe(payload.length)
    const written = await readFile(join(root, 'uploads', id, 'bundle.tar'))
    expect(written.equals(payload)).toBe(true)
    expect((await stat(join(root, 'uploads', id, 'bundle.tar'))).mode & 0o777).toBe(0o600)
    expect(code(await call(`/api/system/offline/uploads/${id}`, { method: 'PUT', client: admin, body: payload }))).toBe('E_UPLOAD')

    const empty = (await post('/api/system/offline/uploads', admin)).data.upload_id as string
    expect(code(await call(`/api/system/offline/uploads/${empty}`, { method: 'PUT', client: admin, body: '' }))).toBe('E_UPLOAD')
  })

  it('import : fichier téléversé exigé ; échec du helper tracé avec son code', async () => {
    const url = '/api/system/offline/import'
    expect(code(await post(url, admin, { upload_id: '../x' }))).toBe('E_VALIDATION')
    const missing = (await post('/api/system/offline/uploads', admin)).data.upload_id as string
    expect(code(await post(url, admin, { upload_id: missing }))).toBe('E_UPLOAD')
    // Lien symbolique à la place du fichier : refusé par la console aussi.
    await symlink('/etc/hostname', join(root, 'uploads', missing, 'bundle.tar'))
    expect(code(await post(url, admin, { upload_id: missing }))).toBe('E_UPLOAD')

    const id = (await post('/api/system/offline/uploads', admin)).data.upload_id as string
    await call(`/api/system/offline/uploads/${id}`, { method: 'PUT', client: admin, body: randomBytes(1024) })
    expect(code(await post(url, operator, { upload_id: id }))).toBe('E_FORBIDDEN')
    const r = await post(url, admin, { upload_id: id })
    expect(r.status).toBe(202)
    expect((await incoming(r.data.request_id))?.doc.params).toEqual({ upload_id: id })
    await complete(r.data.request_id, false, {}, 'E_BUNDLE_SIGNATURE')
    const row = await db.pool.query('SELECT direction, status, error FROM offline_bundles WHERE request_id = $1', [r.data.request_id])
    expect(row.rows).toEqual([{ direction: 'import', status: 'error', error: { code: 'E_BUNDLE_SIGNATURE', message: 'invalid bundle signature' } }])
    const view = await call('/api/system/offline', { client: operator })
    expect(view.data.history.some((h: Json) => h.direction === 'import' && h.status === 'error')).toBe(true)
  })

  it('miroir : https seulement, empreinte exigée, retrait sans paramètre', async () => {
    const url = '/api/system/offline/mirror'
    for (const json of [
      { enabled: true, url: 'http://mirror.analyse.exemple.test', fingerprint: FPR },
      { enabled: true, url: 'https://mirror.analyse.exemple.test' },
      { enabled: true, url: 'https://mirror.analyse.exemple.test/../x', fingerprint: FPR },
      { enabled: false, url: 'https://mirror.analyse.exemple.test' },
    ]) {
      expect(code(await post(url, admin, json)), JSON.stringify(json)).toBe('E_VALIDATION')
    }
    expect(code(await post(url, operator, { enabled: false }))).toBe('E_FORBIDDEN')
    const r = await post(url, admin, { enabled: true, url: 'https://mirror.analyse.exemple.test', fingerprint: FPR })
    expect(r.status).toBe(202)
    expect((await incoming(r.data.request_id))?.doc).toMatchObject({ type: 'set-mirror', params: { enabled: true, url: 'https://mirror.analyse.exemple.test', fingerprint: FPR } })
    const off = await post(url, admin, { enabled: false })
    expect((await incoming(off.data.request_id))?.doc.params).toEqual({ enabled: false })
  })

  it('téléchargement : admin, nom contrôlé, lien refusé, flux complet et audit', async () => {
    const content = randomBytes(64 * 1024)
    await writeFile(join(root, 'bundles', BUNDLE), content)
    expect(code(await call(`/api/system/offline/bundles/${BUNDLE}`, { client: operator }))).toBe('E_FORBIDDEN')
    for (const name of ['..%2Fstate.json', 'scanoria-bundle-x.tar', 'scanoria-bundle-20261124T020000Z.tar.json']) {
      expect(code(await call(`/api/system/offline/bundles/${name}`, { client: admin })), name).toBe('E_NOT_FOUND')
    }
    const linked = 'scanoria-bundle-20261124T030000Z.tar'
    await symlink(join(root, 'state.json'), join(root, 'bundles', linked))
    expect(code(await call(`/api/system/offline/bundles/${linked}`, { client: admin }))).toBe('E_NOT_FOUND')
    const res = await fetch(`${base}/api/system/offline/bundles/${BUNDLE}`, { headers: { 'cookie': admin.cookie, 'x-real-ip': '198.51.100.200' } })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-disposition')).toBe(`attachment; filename="${BUNDLE}"`)
    expect(Buffer.from(await res.arrayBuffer()).equals(content)).toBe(true)
    const audit = await call('/api/audit?action=offline.bundle-download', { client: admin })
    expect(JSON.stringify(audit.data)).toContain(BUNDLE)
  })

  it('audit : chaque demande hors ligne est tracée sans clé privée', async () => {
    const audit = await call('/api/audit?action=system.trust-key.request', { client: admin })
    expect(audit.status).toBe(200)
    expect(JSON.stringify(audit.data)).toContain(FPR)
    expect(JSON.stringify(audit.data)).not.toContain('PRIVATE')
  })
})
