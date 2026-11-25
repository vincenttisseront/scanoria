// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API du connecteur IA (/api/ai/*) dans le processus, contre un vrai
// PostgreSQL 16 : rôles, modale confirmée obligatoire, demande set-ai-endpoint
// déposée sans jeton, état affiché (modèles et pourquoi, banc d'essai,
// disjoncteur, latence, file), choix de modèle tracé, demandes d'explication
// cloisonnées et sorties lues, console identique sans connecteur.

import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createSession, csrfTokenFor, SESSION_COOKIE } from '../../server/utils/sessions'
import { getAuthSettings } from '../../server/utils/settings'
import { createUser } from '../../server/utils/users'
import { clearConnectorCache } from '../../server/ai/enqueue'
import { readToken, setTokenStore } from '../../server/ai/token'
import type { AiEndpoint } from '../../server/ai/config'

const ROUTES: [string, string, string][] = [
  ['get', '/api/ai/status', 'status.get'],
  ['get', '/api/ai/calls', 'calls.get'],
  ['post', '/api/ai/connector', 'connector.post'],
  ['post', '/api/ai/disconnect', 'disconnect.post'],
  ['post', '/api/ai/probe', 'probe.post'],
  ['put', '/api/ai/models', 'models.put'],
  ['post', '/api/ai/explain', 'explain.post'],
  ['get', '/api/ai/output', 'output.get'],
]

interface Client { cookie: string, csrf: string }

// Faux jeton généré à l'exécution : aucun motif de secret dans le dépôt.
const FAKE_TOKEN = randomBytes(12).toString('hex')

describe.skipIf(!DATABASE_URL)('API du connecteur IA (h3, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let operator: Client
  let viewer: Client
  let projectId: string
  let optOutProjectId: string
  let findingId: string
  let optOutFindingId: string
  let scanId: string

  const endpointFile = () => join(root, 'ai.json')
  const statusFile = () => join(root, 'ai-status.json')
  const active: AiEndpoint = {
    version: 1, enabled: true, url: 'https://ollama.exemple.test:11434', scheme: 'https', host: 'ollama.exemple.test',
    port: 11434, addresses: ['192.0.2.10'], insecure: false, token: false, ca: false, literal: false, pinned_at: '2026-11-24T09:00:00Z',
  }
  const writeEndpoint = async (ep: AiEndpoint) => {
    await writeFile(endpointFile(), JSON.stringify(ep))
    clearConnectorCache()
  }

  async function call(path: string, init: { method?: string, client?: Client, json?: unknown } = {}) {
    const headers: Record<string, string> = { 'x-real-ip': '192.0.2.20' }
    if (init.client) {
      headers.cookie = init.client.cookie
      if (init.method && init.method !== 'GET') headers['x-csrf-token'] = init.client.csrf
    }
    let body: string | undefined
    if (init.json !== undefined) {
      headers['content-type'] = 'application/json'
      body = JSON.stringify(init.json)
    }
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body })
    const text = await res.text()
    let data: Record<string, unknown> & { data?: { code?: string } } = {}
    try {
      data = JSON.parse(text)
    }
    catch {
      // corps vide
    }
    return { status: res.status, data }
  }

  async function client(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client> {
    const user = await createUser(db.pool, { username, role, password: `${username}-long-password`, mustChangePassword: false })
    const s = await createSession(db.pool, Number(user.id), await getAuthSettings(db.pool, 0), { ip: '192.0.2.20', userAgent: 'vitest' })
    return { cookie: `${SESSION_COOKIE}=${s.token}`, csrf: csrfTokenFor(s.token) }
  }

  async function incoming(type: string): Promise<Record<string, unknown>[]> {
    const dir = join(root, 'requests', 'incoming')
    const out: Record<string, unknown>[] = []
    for (const name of await readdir(dir)) {
      const r = JSON.parse(await readFile(join(dir, name), 'utf8')) as Record<string, unknown>
      if (r.type === type) out.push(r)
    }
    return out
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-ai-api-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    process.env.NUXT_AI_ENDPOINT_FILE = endpointFile()
    process.env.NUXT_AI_STATUS_FILE = statusFile()
    await writeEndpoint({ version: 1, enabled: false })
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_MIGRATE_ON_START: 'false',
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))
    // Base déjà migrée par createTestDatabase : démarrage sans migration à appliquer.
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const [method, path, file] of ROUTES) {
      router[method as 'get'](path, (await import(`../../server/api/ai/${file}.ts`)).default as EventHandler)
    }
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`

    admin = await client('ai-admin', 'admin')
    operator = await client('ai-operator', 'operator')
    viewer = await client('ai-viewer', 'viewer')

    const pool = db.pool
    const { p, g } = (await pool.query<{ p: string, g: string }>(
      `SELECT (SELECT id FROM profiles WHERE slug = 'rapide') AS p, (SELECT id FROM gates WHERE slug = 'defaut') AS g`,
    )).rows[0]!
    const mk = async (slug: string, optOut: boolean) => (await pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, ai_opt_out) VALUES ($1, $1, 'archive', $2, $3, $4) RETURNING id`,
      [slug, p, g, optOut],
    )).rows[0]!.id
    projectId = await mk('alpha', false)
    optOutProjectId = await mk('secret-project', true)
    const finding = async (project: string, fp: string) => (await pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line)
       VALUES ($1, $2, 'opengrep', 'python.sql', 'sast', 'high', 'SQL injection', 'app/db.py', 3) RETURNING id`,
      [project, fp],
    )).rows[0]!.id
    findingId = await finding(projectId, 'a'.repeat(64))
    optOutFindingId = await finding(optOutProjectId, 'b'.repeat(64))
    scanId = (await pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, verdict)
       VALUES ($1, 1, 'manual', 50, 'main', $2, $3, 'done', 'failed') RETURNING id`,
      [projectId, p, g],
    )).rows[0]!.id
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    delete process.env.NUXT_AI_ENDPOINT_FILE
    delete process.env.NUXT_AI_STATUS_FILE
    clearConnectorCache()
    setTokenStore(null)
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('sans connecteur : état inactif, aucune explication demandable, aucune sortie', async () => {
    const st = await call('/api/ai/status', { client: operator })
    expect(st.status).toBe(200)
    expect(st.data).toMatchObject({ enabled: false, token_stored: false, token_supported: true, circuit: { state: 'closed' }, queue: { queued: 0, running: 0 } })
    expect((st.data.tasks as { state: string }[]).every(t => t.state === 'off')).toBe(true)

    const ex = await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'explain-finding', subject_id: findingId } })
    expect(ex.status).toBe(200)
    expect(ex.data).toEqual({ task_id: null })
    const out = await call(`/api/ai/output?kind=explain-finding&subject_id=${findingId}`, { client: viewer })
    expect(out.data).toEqual({ enabled: false, opt_out: false, task: null })
    expect((await call('/api/ai/probe', { method: 'POST', client: admin, json: {} })).data.data?.code).toBe('E_UNAVAILABLE')
  })

  it('rôles : lecteur sans état, opérateur sans écriture', async () => {
    expect((await call('/api/ai/status', { client: viewer })).status).toBe(403)
    expect((await call('/api/ai/calls', { client: viewer })).status).toBe(403)
    expect((await call('/api/ai/connector', { method: 'POST', client: operator, json: { url: 'https://ollama.exemple.test:11434', confirmed: true } })).status).toBe(403)
    expect((await call('/api/ai/disconnect', { method: 'POST', client: operator, json: {} })).status).toBe(403)
    expect((await call('/api/ai/models', { method: 'PUT', client: operator, json: { models: {} } })).status).toBe(403)
    expect((await call('/api/ai/status')).status).toBe(401)
  })

  it('activation : confirmation obligatoire, http explicite, jamais de jeton dans la demande', async () => {
    const noConfirm = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434' } })
    expect(noConfirm.status).toBe(400)
    const http = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'http://192.0.2.10:11434', confirmed: true } })
    expect(http.status).toBe(400)
    const httpToken = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'http://192.0.2.10:11434', allow_insecure: true, token: FAKE_TOKEN, confirmed: true } })
    expect(httpToken.status).toBe(400)
    const path = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434/api', confirmed: true } })
    expect(path.status).toBe(400)
    const ok = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'http://192.0.2.10:11434', allow_insecure: true, confirmed: true } })
    expect(ok.status, JSON.stringify(ok.data)).toBe(202)
    const reqs = await incoming('set-ai-endpoint')
    expect(reqs).toHaveLength(1)
    expect(reqs[0]!.params).toEqual({ enabled: true, url: 'http://192.0.2.10:11434', allow_insecure: true })

    const audit = await db.pool.query(`SELECT details FROM audit_log WHERE action = 'system.set-ai-endpoint.request' ORDER BY id DESC LIMIT 1`)
    expect(audit.rows[0]?.details).toMatchObject({ url: 'http://192.0.2.10:11434', confirmed: true })
  })

  it('vérification du certificat : active par défaut, désactivable en https seulement, jamais avec une AC', async () => {
    const pem = `-----BEGIN CERTIFICATE-----\n${'Q'.repeat(80)}\n-----END CERTIFICATE-----\n`
    const httpSkip = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'http://192.0.2.10:11434', allow_insecure: true, skip_tls_verify: true, confirmed: true } })
    expect(httpSkip.status).toBe(400)
    const caSkip = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', ca_pem: pem, skip_tls_verify: true, confirmed: true } })
    expect(caSkip.status).toBe(400)
    const ok = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', skip_tls_verify: true, confirmed: true } })
    expect(ok.status, JSON.stringify(ok.data)).toBe(202)
    const reqs = (await incoming('set-ai-endpoint')).filter(r => (r.params as Record<string, unknown>).skip_tls_verify !== undefined)
    expect(reqs.map(r => r.params)).toEqual([{ enabled: true, url: 'https://ollama.exemple.test:11434', skip_tls_verify: true }])
    const audit = await db.pool.query(`SELECT details FROM audit_log WHERE action = 'system.set-ai-endpoint.request' ORDER BY id DESC LIMIT 1`)
    expect(audit.rows[0]?.details).toMatchObject({ url: 'https://ollama.exemple.test:11434', tls_verify: false })
  })

  it('jeton : enregistré par le magasin injecté, signalé au helper, retiré sur demande', async () => {
    const saved: string[] = []
    setTokenStore({
      save: async (_db, value) => {
        saved.push(value)
        return '00000000-0000-4000-8000-000000000001'
      },
      read: async () => '',
    })
    const r = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', token: FAKE_TOKEN, confirmed: true } })
    expect(r.status, JSON.stringify(r.data)).toBe(202)
    expect(saved).toEqual([FAKE_TOKEN])
    const last = (await incoming('set-ai-endpoint')).find(x => (x.params as { token?: boolean }).token)
    expect(last!.params).toEqual({ enabled: true, url: 'https://ollama.exemple.test:11434', token: true })
    expect(JSON.stringify(last)).not.toContain(FAKE_TOKEN)
    // Jeton enregistré : http refusé.
    const http = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'http://192.0.2.10:11434', allow_insecure: true, confirmed: true } })
    expect(http.status).toBe(400)
    const removed = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', token: null, confirmed: true } })
    expect(removed.status).toBe(202)
    expect((await call('/api/ai/status', { client: operator })).data.token_stored).toBe(false)
    setTokenStore(null)
  })

  it('jeton : chiffré pour de vrai par la clé dédiée, l\'ancien supprimé au remplacement', async () => {
    process.env.NUXT_AI_TOKEN_KEY_FILE = join(root, 'ai-token.key')
    try {
      setTokenStore(null)
      const first = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', token: FAKE_TOKEN, confirmed: true } })
      expect(first.status, JSON.stringify(first.data)).toBe(202)
      const rows = async () => (await db.pool.query<{ id: string, secret_enc: Buffer }>(`SELECT id::text, secret_enc FROM credentials WHERE kind = 'ai-token'`)).rows
      const [one] = await rows()
      expect(one).toBeDefined()
      expect(Buffer.from(one!.secret_enc).toString('latin1')).not.toContain(FAKE_TOKEN)
      expect((await stat(join(root, 'ai-token.key'))).mode & 0o777).toBe(0o600)
      expect(await readToken(db.pool, one!.id)).toBe(FAKE_TOKEN)
      const second = await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', token: `${FAKE_TOKEN}x`, confirmed: true } })
      expect(second.status).toBe(202)
      const after = await rows()
      expect(after).toHaveLength(1)
      expect(after[0]!.id).not.toBe(one!.id)
      await call('/api/ai/connector', { method: 'POST', client: admin, json: { url: 'https://ollama.exemple.test:11434', token: null, confirmed: true } })
      expect(await rows()).toHaveLength(0)
    }
    finally {
      delete process.env.NUXT_AI_TOKEN_KEY_FILE
    }
  })

  it('retrait du connecteur : demande enabled:false', async () => {
    const r = await call('/api/ai/disconnect', { method: 'POST', client: admin, json: {} })
    expect(r.status).toBe(202)
    expect((await incoming('set-ai-endpoint')).some(x => JSON.stringify(x.params) === '{"enabled":false}')).toBe(true)
  })

  it('connecteur actif : modèles et raisons, banc d\'essai, latence, disjoncteur, résolution et candidat', async () => {
    await writeEndpoint(active)
    await writeFile(statusFile(), JSON.stringify({
      version: 1, checked_at: '2026-11-24T10:00:00Z', enabled: true,
      resolution: { pinned: ['192.0.2.10'], current: ['192.0.2.11'], changed: true, error: null },
      candidate: null,
    }))
    const digest = 'c'.repeat(64)
    const pool = db.pool
    await pool.query(
      `INSERT INTO ai_tasks (kind, subject_type, subject_id, priority, status, output, finished_at)
       VALUES ('probe', 'testbed', 'connector', 70, 'done', $1, now())`,
      [JSON.stringify({
        version: '0.12.3',
        models: [{ name: 'qwen-test:14b', digest, capabilities: ['completion'], context: 32768, parameters_b: 14.8, family: 'qwen2' }],
        selection: {
          tasks: { 'explain-finding': { model: 'qwen-test:14b', digest, reason: 'only-model' }, 'explain-verdict': { model: 'qwen-test:14b', digest, reason: 'only-model' } },
          embedding: null,
        },
      })],
    )
    await pool.query(
      `INSERT INTO ai_tasks (kind, subject_type, subject_id, priority, status, output, model, model_digest, finished_at)
       VALUES ('testbed', 'testbed', 'explain-finding', 80, 'done', $1, 'qwen-test:14b', $2, now()),
              ('testbed', 'testbed', 'explain-verdict', 80, 'done', $3, 'qwen-test:14b', $2, now())`,
      [JSON.stringify({ score: 1, threshold: 0.75, passed: true, cases: [] }), digest, JSON.stringify({ score: 0.5, threshold: 0.75, passed: false, cases: [] })],
    )
    await pool.query(
      `INSERT INTO ai_calls (kind, project_id, model, bytes_sent, duration_ms, outcome)
       VALUES ('explain-finding', $1, 'qwen-test:14b', 1200, 400, 'ok'), ('explain-finding', $1, 'qwen-test:14b', 1000, 200, 'ok')`,
      [projectId],
    )
    const st = await call('/api/ai/status', { client: operator })
    expect(st.data).toMatchObject({
      enabled: true,
      endpoint: { url: 'https://ollama.exemple.test:11434', addresses: ['192.0.2.10'] },
      check: { resolution: { changed: true, current: ['192.0.2.11'] } },
      probe: { status: 'done', version: '0.12.3' },
      latency_ms: 300,
      circuit: { state: 'closed' },
    })
    const tasks = st.data.tasks as { kind: string, state: string, model: { reason: string } }[]
    expect(tasks.find(t => t.kind === 'explain-finding')).toMatchObject({ state: 'active', model: { reason: 'only-model' } })
    expect(tasks.find(t => t.kind === 'explain-verdict')!.state).toBe('disabled')

    const calls = await call('/api/ai/calls?limit=5', { client: operator })
    expect(calls.data.calls).toHaveLength(2)
    expect((calls.data.calls as { project: string }[])[0]!.project).toBe('alpha')

    await pool.query(
      `INSERT INTO ai_calls (kind, model, bytes_sent, outcome) VALUES ('probe', null, 0, 'error'), ('probe', null, 0, 'timeout'), ('probe', null, 0, 'error')`,
    )
    expect((await call('/api/ai/status', { client: operator })).data.circuit).toMatchObject({ state: 'open' })
  })

  it('choix d\'un modèle : enregistré, tracé, puis retour automatique ; nouvelle découverte déposée', async () => {
    const set = await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { 'explain-verdict': 'qwen-test:14b' } } })
    expect(set.status, JSON.stringify(set.data)).toBe(200)
    let st = await call('/api/ai/status', { client: operator })
    expect((st.data.tasks as { kind: string, override: string | null }[]).find(t => t.kind === 'explain-verdict')!.override).toBe('qwen-test:14b')
    const audit = await db.pool.query(`SELECT count(*)::int AS n FROM audit_log WHERE action = 'ai.models.update'`)
    expect(audit.rows[0].n).toBe(1)
    expect((await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { 'rm-rf': 'x' } } })).status).toBe(400)
    await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { 'explain-verdict': null } } })
    st = await call('/api/ai/status', { client: operator })
    expect((st.data.tasks as { override: string | null }[]).every(t => t.override === null)).toBe(true)

    const probe = await call('/api/ai/probe', { method: 'POST', client: admin, json: {} })
    expect(probe.status).toBe(202)
    const queued = await db.pool.query(`SELECT count(*)::int AS n FROM ai_tasks WHERE kind = 'probe' AND status = 'queued'`)
    expect(queued.rows[0].n).toBe(1)

    // Découverte en attente visible par la console (indicateur d'attente).
    expect((await call('/api/ai/status', { client: operator })).data.probe).toMatchObject({ pending: true })

    // Liste déroulante globale : rédaction pour toutes les tâches, embedding, nom libre de secours.
    const globals = await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { default: 'qwen-test:14b', embedding: 'nomic-embed-text' } } })
    expect(globals.status, JSON.stringify(globals.data)).toBe(200)
    st = await call('/api/ai/status', { client: operator })
    expect(st.data.defaults).toEqual({ generation: 'qwen-test:14b', embedding: 'nomic-embed-text' })
    expect((await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { default: 'bad name; rm' } } })).status).toBe(400)
    await call('/api/ai/models', { method: 'PUT', client: admin, json: { models: { default: null, embedding: null } } })
    expect((await call('/api/ai/status', { client: operator })).data.defaults).toEqual({ generation: null, embedding: null })
  })

  it('explications : demande interactive, sortie lue, projet exclu respecté, sujet inconnu', async () => {
    const ex = await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'explain-finding', subject_id: findingId, locale: 'en' } })
    expect(ex.status).toBe(202)
    const taskId = String(ex.data.task_id)
    const row = (await db.pool.query('SELECT priority, locale, project_id FROM ai_tasks WHERE id = $1', [taskId])).rows[0]
    expect(row).toMatchObject({ priority: 50, locale: 'en', project_id: projectId })

    let out = await call(`/api/ai/output?kind=explain-finding&subject_id=${findingId}&locale=en`, { client: viewer })
    expect(out.data).toMatchObject({ enabled: true, opt_out: false, task: { status: 'queued', output: null } })
    await db.pool.query(
      `UPDATE ai_tasks SET status = 'done', output = $2, model = 'qwen-test:14b', model_digest = $3, finished_at = now() WHERE id = $1`,
      [taskId, JSON.stringify({ summary: 'SQL injection.' }), 'c'.repeat(64)],
    )
    out = await call(`/api/ai/output?kind=explain-finding&subject_id=${findingId}`, { client: viewer })
    expect(out.data).toMatchObject({ task: { status: 'done', output: { summary: 'SQL injection.' }, model: 'qwen-test:14b', stale: false } })
    // Autre modèle retenu depuis : sortie signalée comme périmée.
    await db.pool.query(
      `UPDATE ai_tasks SET output = jsonb_set(output, '{selection,tasks,explain-finding,digest}', to_jsonb($1::text)) WHERE kind = 'probe' AND status = 'done'`,
      ['d'.repeat(64)],
    )
    out = await call(`/api/ai/output?kind=explain-finding&subject_id=${findingId}`, { client: viewer })
    expect(out.data).toMatchObject({ task: { status: 'done', stale: true } })
    // Connecteur retiré : plus rien d'affiché, même les sorties déjà produites.
    await writeEndpoint({ version: 1, enabled: false })
    out = await call(`/api/ai/output?kind=explain-finding&subject_id=${findingId}`, { client: viewer })
    expect(out.data).toEqual({ enabled: false, opt_out: false, task: null })
    await writeEndpoint(active)

    const opt = await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'explain-finding', subject_id: optOutFindingId } })
    expect(opt.data).toEqual({ task_id: null })
    const optOut = await call(`/api/ai/output?kind=explain-finding&subject_id=${optOutFindingId}`, { client: viewer })
    expect(optOut.data).toMatchObject({ opt_out: true, task: null })

    const verdict = await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'explain-verdict', subject_id: scanId } })
    expect(verdict.status).toBe(202)
    // Mauvais type de sujet : un id de résultat n'est pas une analyse.
    expect((await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'explain-verdict', subject_id: findingId } })).status).toBe(404)
    expect((await call(`/api/ai/output?kind=explain-verdict&subject_id=${findingId}`, { client: viewer })).status).toBe(404)
    expect((await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'probe', subject_id: findingId } })).status).toBe(400)
  })
})
