// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API IA de la 0.4 dans le processus, contre un vrai PostgreSQL 16 : retours
// I24 (vote, correction masquée, taux d'accord par tâche et par modèle),
// suggestions en lot (I3, I14) sans effet sur les statuts, traduction d'une
// règle (sujet sans projet, I17), réglage proposé par un diagnostic (I15)
// recalculé côté serveur et appliqué par un clic tracé, rôles, et console
// identique sans connecteur.

import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
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
import { loadTimeoutOverrides } from '../../server/ai/overrides'
import { resolveProfile, type PlanCatalogEntry } from '../../server/scans/plan'
import type { AiEndpoint } from '../../server/ai/config'

const ROUTES: [string, string, string][] = [
  ['post', '/api/ai/feedback', 'feedback.post'],
  ['get', '/api/ai/agreement', 'agreement.get'],
  ['get', '/api/ai/suggestions', 'suggestions.get'],
  ['post', '/api/ai/explain', 'explain.post'],
  ['get', '/api/ai/output', 'output.get'],
  ['get', '/api/ai/rule-key', 'rule-key.get'],
]

interface Client { cookie: string, csrf: string }

describe.skipIf(!DATABASE_URL)('API IA de la 0.4 (h3, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let operator: Client
  let viewer: Client
  let viewerId: number
  let alpha: string
  let hidden: string
  let findingId: string
  let hiddenFindingId: string
  let scanId: string
  let triageTask: string
  let hiddenTask: string
  const digest = 'e'.repeat(64)

  const endpointFile = () => join(root, 'ai.json')
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

  async function client(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client & { id: number }> {
    const user = await createUser(db.pool, { username, role, password: `${username}-long-password`, mustChangePassword: false })
    const s = await createSession(db.pool, Number(user.id), await getAuthSettings(db.pool, 0), { ip: '192.0.2.20', userAgent: 'vitest' })
    return { cookie: `${SESSION_COOKIE}=${s.token}`, csrf: csrfTokenFor(s.token), id: Number(user.id) }
  }

  const doneTask = async (kind: string, project: string | null, subjectType: string, subject: string, output: unknown, model = 'qwen-test:14b') =>
    (await db.pool.query<{ id: string }>(
      `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, status, output, model, model_digest, finished_at)
       VALUES ($1, $2, $3, $4, 'done', $5, $6, $7, now() - interval '1 minute') RETURNING id`,
      [kind, project, subjectType, subject, JSON.stringify(output), model, digest],
    )).rows[0]!.id

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-ai-api04-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    process.env.NUXT_AI_ENDPOINT_FILE = endpointFile()
    process.env.NUXT_AI_STATUS_FILE = join(root, 'ai-status.json')
    await writeEndpoint({ version: 1, enabled: false })
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_MIGRATE_ON_START: 'false',
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)
    const app = createApp()
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const [method, path, file] of ROUTES) {
      router[method as 'get'](path, (await import(`../../server/api/ai/${file}.ts`)).default as EventHandler)
    }
    router.get('/api/ai/diagnosis/proposal', (await import('../../server/api/ai/diagnosis/proposal.get')).default as EventHandler)
    router.post('/api/ai/diagnosis/apply', (await import('../../server/api/ai/diagnosis/apply.post')).default as EventHandler)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
    admin = await client('ai-admin', 'admin')
    operator = await client('ai-operator', 'operator')
    const v = await client('ai-viewer', 'viewer')
    viewer = v
    viewerId = v.id

    const pool = db.pool
    const { p, g } = (await pool.query<{ p: string, g: string }>(
      `SELECT (SELECT id FROM profiles WHERE slug = 'rapide') AS p, (SELECT id FROM gates WHERE slug = 'defaut') AS g`,
    )).rows[0]!
    const mk = async (slug: string, optOut: boolean) => (await pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, ai_opt_out) VALUES ($1, $1, 'archive', $2, $3, $4) RETURNING id`,
      [slug, p, g, optOut],
    )).rows[0]!.id
    alpha = await mk('alpha', false)
    hidden = await mk('hidden', true)
    const finding = async (project: string) => (await pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, start_line)
       VALUES ($1, $2, 'semgrep', 'python.sqli', 'sast', 'high', 'SQL query built with string formatting', 'app/db.py', 3) RETURNING id`,
      [project, randomBytes(32).toString('hex')],
    )).rows[0]!.id
    findingId = await finding(alpha)
    hiddenFindingId = await finding(hidden)
    const plan = {
      version: 1, created_at: '2026-11-24T09:00:00Z',
      source: { kind: 'archive', ref: 'main', commit: null, history: 'shallow' },
      profile: { id: p, slug: 'rapide', categories: ['secrets'], include_modules: [], exclude_modules: [] },
      gate: { id: g, slug: 'defaut', rules: { new_code_only: true, max_secrets: 0, vuln_block_from: 'high', sast_block_from: 'high', iac_block_from: 'high', block_malicious: true, inconclusive_blocks: true } },
      modules: [{ id: 'semgrep', version: '1.0.0', image: null, image_digest: null, categories: ['sast'], options: {}, feeds: [], timeout_s: 900, history: 'shallow', outputs: ['sarif'], reason: 'category' }],
      gaps: [],
      timeout_s: 900,
    }
    scanId = (await pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, verdict, plan)
       VALUES ($1, 1, 'manual', 50, 'main', $2, $3, 'done', 'inconclusive', $4) RETURNING id`,
      [alpha, p, g, JSON.stringify(plan)],
    )).rows[0]!.id
    await pool.query(
      `INSERT INTO scan_modules (scan_id, module_id, module_version, status, error_class, attempts, duration_ms) VALUES ($1, 'semgrep', '1.0.0', 'timeout', 'infra', 1, 900000)`,
      [scanId],
    )
    triageTask = await doneTask('triage-finding', alpha, 'finding', findingId, { suggestion: 'likely-false-positive', summary: 'S', reasons: [{ kind: 'test-code', quote: 'app/db.py', explanation: 'E', cited: true }], downgraded: false })
    hiddenTask = await doneTask('triage-finding', hidden, 'finding', hiddenFindingId, { suggestion: 'likely-true-positive', summary: 'S', reasons: [] })
    await doneTask('probe', null, 'testbed', 'connector', { selection: { tasks: { 'triage-finding': { model: 'qwen-test:14b', digest, context: 8192, reason: 'only-model' } }, embedding: null } }, '')
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    delete process.env.NUXT_AI_ENDPOINT_FILE
    delete process.env.NUXT_AI_STATUS_FILE
    clearConnectorCache()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('sans connecteur : aucune suggestion, aucune sortie ; la console reste celle d\'une appliance sans IA', async () => {
    const s = await call(`/api/ai/suggestions?kind=triage-finding&ids=${findingId}`, { client: viewer })
    expect(s.data).toEqual({ enabled: false, items: {} })
    const out = await call(`/api/ai/output?kind=triage-finding&subject_id=${findingId}`, { client: viewer })
    expect(out.data).toMatchObject({ enabled: false, task: null })
  })

  it('suggestions en lot : indice et modèle, jamais pour un projet exclu ; statut inchangé', async () => {
    await writeEndpoint(active)
    const r = await call(`/api/ai/suggestions?kind=triage-finding&ids=${findingId},${hiddenFindingId},${findingId}`, { client: viewer })
    expect(r.status).toBe(200)
    expect(r.data).toEqual({ enabled: true, items: { [findingId]: { value: 'likely-false-positive', model: 'qwen-test:14b', model_digest: digest } } })
    expect((await call(`/api/ai/suggestions?kind=explain-finding&ids=${findingId}`, { client: viewer })).status).toBe(400)
    expect((await call('/api/ai/suggestions?kind=triage-finding&ids=x', { client: viewer })).status).toBe(400)
    expect((await call(`/api/ai/suggestions?kind=triage-finding&ids=${findingId}`)).status).toBe(401)
    expect((await db.pool.query('SELECT status FROM findings WHERE id = $1', [findingId])).rows[0]!.status).toBe('new')
  })

  it('I24 : vote et correction masquée, remplacés par un nouveau vote, rendus avec la sortie', async () => {
    const correction = `Not a false positive: the key ${['gh', 'p_'].join('')}${randomBytes(27).toString('base64url').replace(/[^A-Za-z0-9]/g, 'k').slice(0, 36)} is live`
    const r = await call('/api/ai/feedback', { method: 'POST', client: viewer, json: { task_id: triageTask, vote: -1, correction } })
    expect(r.status, JSON.stringify(r.data)).toBe(200)
    const row = (await db.pool.query('SELECT vote, correction, user_id FROM ai_feedback WHERE task_id = $1', [triageTask])).rows[0]!
    expect(row.vote).toBe(-1)
    expect(Number(row.user_id)).toBe(viewerId)
    expect(row.correction).toContain('[secret masqué')
    expect(row.correction).not.toMatch(/gh[p]_[A-Za-z0-9]{30}/)
    const out = await call(`/api/ai/output?kind=triage-finding&subject_id=${findingId}`, { client: viewer })
    expect((out.data.task as { feedback: unknown }).feedback).toMatchObject({ vote: -1 })
    await call('/api/ai/feedback', { method: 'POST', client: viewer, json: { task_id: triageTask, vote: 1 } })
    expect((await db.pool.query('SELECT count(*)::int AS n, max(vote) AS v FROM ai_feedback WHERE task_id = $1', [triageTask])).rows[0]).toEqual({ n: 1, v: 1 })
    await call('/api/ai/feedback', { method: 'POST', client: operator, json: { task_id: triageTask, vote: -1 } })
  })

  it('I24 : refusé pour une sortie d\'un projet exclu, inconnue ou mal formée', async () => {
    expect((await call('/api/ai/feedback', { method: 'POST', client: viewer, json: { task_id: hiddenTask, vote: 1 } })).status).toBe(404)
    expect((await call('/api/ai/feedback', { method: 'POST', client: viewer, json: { task_id: '00000000-0000-4000-8000-000000000000', vote: 1 } })).status).toBe(404)
    expect((await call('/api/ai/feedback', { method: 'POST', client: viewer, json: { task_id: triageTask, vote: 2 } })).status).toBe(400)
    expect((await call('/api/ai/feedback', { method: 'POST', json: { task_id: triageTask, vote: 1 } })).status).toBe(401)
  })

  it('I24 : taux d\'accord par tâche et modèle, y compris le pré-tri comparé au tri humain', async () => {
    await db.pool.query(`UPDATE findings SET status = 'false-positive', status_by = $2, status_at = now(), status_reason = 'test' WHERE id = $1`, [findingId, viewerId])
    expect((await call('/api/ai/agreement', { client: viewer })).status).toBe(403)
    const r = await call('/api/ai/agreement', { client: operator })
    expect(r.status).toBe(200)
    const items = r.data.items as { kind: string, model: string, votes: number, up: number, rate: number, triaged: number, matched: number, triage_rate: number }[]
    expect(items).toEqual([{ kind: 'triage-finding', model: 'qwen-test:14b', votes: 2, up: 1, rate: 0.5, triaged: 1, matched: 1, triage_rate: 1 }])
  })

  it('I17 : clé de règle calculée par le serveur ; aucune pour un projet exclu ; 404 et 400', async () => {
    await db.pool.query(`UPDATE findings SET last_scan_id = $1 WHERE id = $2`, [scanId, findingId])
    expect((await call(`/api/ai/rule-key?finding_id=${findingId}`, { client: viewer })).data).toEqual({ key: 'semgrep:1.0.0:python.sqli' })
    expect((await call(`/api/ai/rule-key?finding_id=${hiddenFindingId}`, { client: viewer })).data).toEqual({ key: null })
    expect((await call('/api/ai/rule-key?finding_id=99999999-9999-4999-8999-999999999999', { client: viewer })).status).toBe(404)
    expect((await call('/api/ai/rule-key?finding_id=x', { client: viewer })).status).toBe(400)
    expect((await call(`/api/ai/rule-key?finding_id=${findingId}`)).status).toBe(401)
  })

  it('I17 : traduction d\'une règle lue sans projet ; clé invalide refusée', async () => {
    const key = 'semgrep:1.0.0:python.sqli'
    await doneTask('translate-rule', null, 'rule', key, { translation: 'Requête SQL construite par formatage de chaîne' })
    const r = await call(`/api/ai/output?kind=translate-rule&subject_id=${encodeURIComponent(key)}&locale=fr`, { client: viewer })
    expect(r.status).toBe(200)
    expect(r.data).toMatchObject({ enabled: true, opt_out: false, task: { status: 'done', output: { translation: 'Requête SQL construite par formatage de chaîne' } } })
    expect((await call(`/api/ai/output?kind=translate-rule&subject_id=${findingId}`, { client: viewer })).status).toBe(400)
    expect((await call(`/api/ai/output?kind=triage-finding&subject_id=${encodeURIComponent(key)}`, { client: viewer })).status).toBe(400)
    const ex = await call('/api/ai/explain', { method: 'POST', client: viewer, json: { kind: 'translate-rule', subject_id: 'semgrep:1.0.0:other', locale: 'fr' } })
    expect(ex.status).toBe(202)
    expect((await db.pool.query(`SELECT project_id, priority FROM ai_tasks WHERE id = $1`, [ex.data.task_id])).rows[0]).toEqual({ project_id: null, priority: 50 })
  })

  it('I15 : réglage proposé recalculé depuis les faits, appliqué par un clic tracé, pris par le plan suivant', async () => {
    expect((await call(`/api/ai/diagnosis/proposal?scan_id=${scanId}`, { client: viewer })).status).toBe(403)
    const pr = await call(`/api/ai/diagnosis/proposal?scan_id=${scanId}`, { client: operator })
    expect(pr.data).toEqual({ proposal: { kind: 'timeout', module: 'semgrep', current_s: 900, proposed_s: 1800 }, overrides: {} })
    // Valeur affichée périmée ou forgée : refus.
    const forged = await call('/api/ai/diagnosis/apply', { method: 'POST', client: operator, json: { scan_id: scanId, module: 'semgrep', proposed_s: 86_400 } })
    expect(forged.status).toBe(409)
    expect(forged.data.data?.code).toBe('E_AI_STALE')
    expect((await call('/api/ai/diagnosis/apply', { method: 'POST', client: viewer, json: { scan_id: scanId, module: 'semgrep', proposed_s: 1800 } })).status).toBe(403)
    const ok = await call('/api/ai/diagnosis/apply', { method: 'POST', client: operator, json: { scan_id: scanId, module: 'semgrep', proposed_s: 1800 } })
    expect(ok.status, JSON.stringify(ok.data)).toBe(200)
    expect(await loadTimeoutOverrides(db.pool)).toEqual({ semgrep: 1800 })
    const audit = (await db.pool.query(`SELECT details FROM audit_log WHERE action = 'ai.diagnosis.apply'`)).rows
    expect(audit[0]!.details).toMatchObject({ module: 'semgrep', timeout_s: { from: 900, to: 1800 } })
    // Déjà appliqué : plus rien à proposer.
    expect((await call(`/api/ai/diagnosis/proposal?scan_id=${scanId}`, { client: operator })).data.proposal).toBeNull()
    expect((await call('/api/ai/diagnosis/apply', { method: 'POST', client: admin, json: { scan_id: scanId, module: 'semgrep', proposed_s: 1800 } })).status).toBe(404)

    const catalog = new Map<string, PlanCatalogEntry>([['semgrep@1.0.0', {
      id: 'semgrep', version: '1.0.0', type: 'scanner', categories: ['sast'], image: null, restrictions: 'none', feeds: [], outputs: ['sarif'], options: null,
      scan: { inputs: ['archive'], timeout_s: 900 },
    }]])
    const installed = [{ id: 'semgrep', version: '1.0.0', type: 'scanner', status: 'healthy', enabled: true, options: {} }] as never
    const profile = { id: 'p', slug: 'x', categories: ['sast'], include_modules: [], exclude_modules: [] }
    const plain = resolveProfile({ profile, sourceKind: 'archive', projectLicense: null, installed, catalog })
    expect(plain.modules[0]!.timeout_s).toBe(900)
    const longer = resolveProfile({ profile, sourceKind: 'archive', projectLicense: null, installed, catalog, timeoutOverrides: await loadTimeoutOverrides(db.pool) })
    expect(longer.modules[0]!.timeout_s).toBe(1800)
    // Un délai forcé plus court que le manifeste ne raccourcit jamais.
    const shorter = resolveProfile({ profile, sourceKind: 'archive', projectLicense: null, installed, catalog, timeoutOverrides: { semgrep: 60 } })
    expect(shorter.modules[0]!.timeout_s).toBe(900)
  })
})
