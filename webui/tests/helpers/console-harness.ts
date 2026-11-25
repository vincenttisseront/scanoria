// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Console complète dans le processus (h3, vrai PostgreSQL) pour les tests
// d'API du chantier C de la 0.7 : toutes les routes de server/api, sessions
// réelles, configuration dans un répertoire jetable.

import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { createTestDatabase, type TestDatabase } from './db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))

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
      out.push({ method: m[2]!, path: `/api/${segments.map(s => s.replace(/^\[(.+)\]$/, ':$1')).join('/')}`.replace(/\/$/, ''), file: full })
    }
  }
  walk(API_DIR)
  return out.sort((a, b) => a.path.split(':').length - b.path.split(':').length)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Json = Record<string, any>
export interface Client { cookie: string, csrf: string }

export interface Harness {
  db: TestDatabase
  root: string
  call: (path: string, init?: RequestInit & { client?: Client, json?: unknown }) => Promise<{ status: number, data: Json, text: string }>
  login: (username: string, role: 'viewer' | 'operator' | 'admin') => Promise<Client>
  /** Écrit l'état des modules installés et l'index du catalogue lus par la console. */
  setModules: (state: unknown, index: unknown) => Promise<void>
  close: () => Promise<void>
}

let ip = 10

export async function startHarness(prefix: string): Promise<Harness> {
  const db = await createTestDatabase()
  const root = await mkdtemp(join(tmpdir(), `scanoria-${prefix}-`))
  for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap', 'uploads']) {
    await mkdir(join(root, d), { recursive: true, mode: 0o700 })
  }
  process.env.NUXT_SECRET_KEY_FILE = join(root, 'secret.key')
  setConfig(loadConfig({
    NUXT_DATABASE_URL: db.url,
    NUXT_REQUESTS_DIR: join(root, 'requests'),
    NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
    NUXT_STATE_FILE: join(root, 'state.json'),
    NUXT_VERSION_FILE: join(root, 'VERSION'),
    NUXT_UPLOADS_DIR: join(root, 'uploads'),
    NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
    NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
    NUXT_MIGRATE_ON_START: '0',
    NUXT_INGEST_INTERVAL_MS: '60000',
  }))
  void startConsole(async () => [])
  if (!(await waitReady(30_000))) throw new Error('console not ready')
  const app = createApp()
  app.use((await import('../../server/middleware/api-token')).default)
  app.use((await import('../../server/middleware/auth')).default)
  const router = createRouter()
  for (const r of apiRoutes()) router[r.method as 'get'](r.path, (await import(r.file)).default as EventHandler)
  app.use(router)
  const server: Server = createServer(toNodeListener(app))
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`

  const call: Harness['call'] = async (path, init = {}) => {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    headers.set('x-real-ip', '192.0.2.10')
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
    return { status: res.status, data: data as Json, text }
  }
  return {
    db, root, call,
    login: async (username, role) => {
      const password = `${username}-long-password`
      await createUser(db.pool, { username, role, password, mustChangePassword: false })
      const headers = new Headers({ 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++}` })
      const res = await fetch(`${base}/api/auth/login`, { method: 'POST', headers, body: JSON.stringify({ username, password }) })
      const data = await res.json() as Json
      if (res.status !== 200) throw new Error(`login ${username}: ${res.status}`)
      return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
    },
    setModules: async (state, index) => {
      await writeFile(join(root, 'modules-state.json'), JSON.stringify(state))
      await writeFile(join(root, 'catalog-index.json'), JSON.stringify(index))
    },
    close: async () => {
      await new Promise<void>(resolve => server.close(() => resolve()))
      await stopConsole()
      await closePool()
      await db.drop()
      await rm(root, { recursive: true, force: true })
      delete process.env.NUXT_SECRET_KEY_FILE
    },
  }
}
