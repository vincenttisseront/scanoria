// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Banc commun des tests d'API IA de la 0.7 (I8, I12) : vrai PostgreSQL 16,
// faux serveur Ollama, routes de server/api montées dans h3 avec les
// intergiciels d'authentification, connecteur activable, file scanoria-ai
// vidée par le vrai service.

import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { createTestDatabase, type TestDatabase } from './db'
import { startFakeOllama, type FakeOllama } from './fake-ollama'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { AiService } from '../../server/ai/service'
import { OllamaClient } from '../../server/ai/ollama'
import { loadEndpoint, type AiEndpoint } from '../../server/ai/config'
import { clearConnectorCache } from '../../server/ai/enqueue'

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

export interface AiConsole {
  db: TestDatabase
  fake: FakeOllama
  call: (path: string, init?: RequestInit & { client?: Client, json?: unknown }) => Promise<{ status: number, data: Json }>
  login: (username: string, role: 'viewer' | 'operator' | 'admin') => Promise<Client>
  setConnector: (on: boolean) => Promise<void>
  drain: (max?: number) => Promise<void>
  close: () => Promise<void>
}

export async function startAiConsole(prefix: string): Promise<AiConsole> {
  const db = await createTestDatabase()
  const fake = await startFakeOllama()
  const root = await mkdtemp(join(tmpdir(), `scanoria-${prefix}-`))
  for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
    await mkdir(join(root, d), { recursive: true, mode: 0o700 })
  }
  const endpointFile = join(root, 'ai.json')
  const active = (): AiEndpoint => ({
    version: 1, enabled: true, url: `http://ollama.exemple.test:${fake.port}`, scheme: 'http', host: 'ollama.exemple.test',
    port: fake.port, addresses: ['127.0.0.1'], insecure: true, token: false, ca: false, literal: false, pinned_at: '2026-11-24T09:00:00Z',
  })
  const setConnector = async (on: boolean) => {
    await writeFile(endpointFile, JSON.stringify(on ? active() : { version: 1, enabled: false }))
    clearConnectorCache()
  }
  process.env.NUXT_AI_ENDPOINT_FILE = endpointFile
  await setConnector(false)
  setConfig(loadConfig({
    NUXT_DATABASE_URL: db.url,
    NUXT_REQUESTS_DIR: join(root, 'requests'),
    NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
    NUXT_STATE_FILE: join(root, 'state.json'),
    NUXT_MODULES_STATE_FILE: join(root, 'modules.json'),
    NUXT_VERSION_FILE: join(root, 'VERSION'),
    NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
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
  let ip = 20

  const call: AiConsole['call'] = async (path, init = {}) => {
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
    return { status: res.status, data: data as Json }
  }

  const login: AiConsole['login'] = async (username, role) => {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const headers = new Headers({ 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++}` })
    const res = await fetch(`${base}/api/auth/login`, { method: 'POST', headers, body: JSON.stringify({ username, password }) })
    if (res.status !== 200) throw new Error(`login ${username}: ${res.status}`)
    const data = await res.json() as Json
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
  }

  const drain: AiConsole['drain'] = async (max = 200) => {
    const s = new AiService({
      db: db.pool,
      loadEndpoint: () => loadEndpoint(endpointFile),
      clientFor: async ep => new OllamaClient({ scheme: ep.scheme, host: ep.host, port: ep.port, addresses: ep.addresses }),
    })
    for (let i = 0; i < max; i++) {
      const r = await s.tick()
      if (r.state === 'idle' || (r.state === 'waiting' && r.ms > 0)) return
    }
    throw new Error('queue did not drain')
  }

  const close = async () => {
    delete process.env.NUXT_AI_ENDPOINT_FILE
    clearConnectorCache()
    await new Promise(resolve => server.close(resolve))
    await fake.close()
    stopConsole()
    await closePool()
    await db.drop()
    await rm(root, { recursive: true, force: true })
  }

  return { db, fake, call, login, setConnector, drain, close }
}
