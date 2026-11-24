// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sauvegarde et restauration des modules permanents (0.4, chantier A), contre
// un vrai PostgreSQL 16 : droits, module non permanent, sauvegarde inconnue ou
// d'une autre version, demandes déposées au service root et audit.

import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>

interface Client {
  cookie: string
  csrf: string
}

const ROUTES: [method: 'get' | 'post', path: string, file: string][] = [
  ['post', '/api/auth/login', '../../server/api/auth/login.post.ts'],
  ['get', '/api/audit', '../../server/api/audit/index.get.ts'],
  ['post', '/api/catalog/modules/:id/backup', '../../server/api/catalog/modules/[id]/backup.post.ts'],
  ['post', '/api/catalog/modules/:id/restore', '../../server/api/catalog/modules/[id]/restore.post.ts'],
]

const BACKUP = {
  created_at: '2026-11-23T02:00:00Z',
  reason: 'manual',
  size_bytes: 1048576,
  database: true,
  volumes: ['data'],
}

const MODULES_STATE = {
  version: 1,
  updated_at: '2026-11-23T08:00:30Z',
  modules: [
    { id: 'gitleaks', version: '8.27.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-20T10:00:00Z', options: {}, testbed: null, route: null, last_error: null },
    {
      id: 'svc', version: '1.2.0', type: 'service', status: 'healthy', enabled: true, installed_at: '2026-11-20T10:00:00Z',
      options: {}, testbed: null, route: { hostname: 'svc.analyse.exemple.test', url: 'https://svc.analyse.exemple.test/' }, last_error: null,
      backups: [
        { ...BACKUP, id: '20261123T020000Z', module_version: '1.2.0' },
        { ...BACKUP, id: '20261120T020000Z', module_version: '1.1.0', reason: 'update' },
      ],
    },
  ],
  operations: [],
}

describe.skipIf(!DATABASE_URL)('services : sauvegarde et restauration des modules (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let viewer: Client
  let ip = 10

  async function call(path: string, init: { method?: string, client?: Client, json?: unknown } = {}) {
    const headers = new Headers({ 'x-real-ip': `198.51.100.${ip++}` })
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method === 'POST') headers.set('x-csrf-token', init.client.csrf)
    }
    if (init.json !== undefined) headers.set('content-type', 'application/json')
    const res = await fetch(`${base}${path}`, { method: init.method, headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
    return { status: res.status, data: (await res.json()) as Json }
  }
  const code = (res: { data: Json }) => res.data?.data?.code as string | undefined
  const post = (path: string, client: Client, json: unknown = {}) => call(path, { method: 'POST', client, json })

  async function login(username: string, role: 'viewer' | 'admin'): Promise<Client> {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const res = await fetch(`${base}/api/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++}` },
      body: JSON.stringify({ username, password }),
    })
    expect(res.status).toBe(200)
    const data = await res.json() as Json
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
  }

  async function incoming(requestId: unknown, type: string) {
    const dir = join(root, 'requests', 'incoming')
    const docs = await Promise.all((await readdir(dir)).map(async n => JSON.parse(await readFile(join(dir, n), 'utf8')) as Json))
    return docs.find(d => d.id === requestId && d.type === type)
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-services-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    await writeFile(join(root, 'modules-state.json'), JSON.stringify(MODULES_STATE))
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
      NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
      NUXT_DNS_STATUS_FILE: join(root, 'dns-status.json'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '60000',
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
    admin = await login('services-admin', 'admin')
    viewer = await login('services-lecteur', 'viewer')
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    await stopConsole()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('sauvegarde : administrateur seulement, module permanent seulement', async () => {
    expect(code(await post('/api/catalog/modules/svc/backup', viewer))).toBe('E_FORBIDDEN')
    expect(code(await post('/api/catalog/modules/gitleaks/backup', admin))).toBe('E_NOT_PERMANENT')
    expect(code(await post('/api/catalog/modules/absent/backup', admin))).toBe('E_NOT_INSTALLED')
    expect(code(await post('/api/catalog/modules/svc/backup', admin, { stop: true }))).toBe('E_VALIDATION')
    const ok = await post('/api/catalog/modules/svc/backup', admin)
    expect(ok.status, JSON.stringify(ok.data)).toBe(202)
    expect((await incoming(ok.data.request_id, 'backup-module'))?.params).toEqual({ id: 'svc' })
    const audit = await call('/api/audit?action=system.backup-module.request', { client: admin })
    expect(JSON.stringify(audit.data)).toContain('"backups_before":2')
  })

  it('restauration : sauvegarde listée et de la version installée', async () => {
    const url = '/api/catalog/modules/svc/restore'
    expect(code(await post(url, viewer, { backup: '20261123T020000Z' }))).toBe('E_FORBIDDEN')
    for (const json of [{}, { backup: '../x' }, { backup: '20261123T020000Z', force: true }]) {
      expect(code(await post(url, admin, json)), JSON.stringify(json)).toBe('E_VALIDATION')
    }
    const unknown = await post(url, admin, { backup: '20261101T020000Z' })
    expect([unknown.status, code(unknown)]).toEqual([404, 'E_BACKUP_NOT_FOUND'])
    const other = await post(url, admin, { backup: '20261120T020000Z' })
    expect([other.status, code(other)]).toEqual([409, 'E_BACKUP_INVALID'])
    expect(code(await post('/api/catalog/modules/gitleaks/restore', admin, { backup: '20261123T020000Z' }))).toBe('E_BACKUP_NOT_FOUND')
    const ok = await post(url, admin, { backup: '20261123T020000Z' })
    expect(ok.status, JSON.stringify(ok.data)).toBe(202)
    expect((await incoming(ok.data.request_id, 'restore-module'))?.params).toEqual({ id: 'svc', backup: '20261123T020000Z' })
    const audit = await call('/api/audit?action=system.restore-module.request', { client: admin })
    expect(JSON.stringify(audit.data)).toContain('20261123T020000Z')
  })
})
