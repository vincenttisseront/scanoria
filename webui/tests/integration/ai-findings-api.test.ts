// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (contrats 31 et 32) contre un vrai PostgreSQL 16 : un module relié au
// relais IA (scan.network: ai-relay) produit des résultats origin = 'ai',
// écartés du verdict tant qu'une personne ne les a pas confirmés ; lecture du
// modèle par le journal du relais ; confirmation réservée à un compte humain
// operator ou plus, tracée dans l'audit ; accord IA/humain par module (I24) ;
// journal du relais conforme aux contraintes de ai_calls.

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, request, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { finalizeScanFindings, ingestModuleOutputs } from '../../server/findings/ingest'
import { aiModuleAgreement } from '../../server/findings/ai-findings'
import { toolHealth } from '../../server/health/scans'
import { evaluateGate } from '../../server/gates/evaluate'
import { CircuitBreaker } from '../../server/ai/service'
import { Relay, type RelayToken } from '../../server/ai/relay'
import { RELAY_KEY } from '../../server/ai/models'
import type { Role } from '#shared/schemas'
import aiGet from '../../server/api/findings/[id]/ai.get'
import aiConfirm from '../../server/api/findings/[id]/ai-confirm.post'

const sarif = (tool: string, results: unknown[]) => ({ version: '2.1.0', runs: [{ tool: { driver: { name: tool, rules: [] } }, results }] })
const result = (rule: string, uri: string) => ({
  ruleId: rule, level: 'error', message: { text: `faille ${rule}` },
  locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 3 } } }],
})

describe.skipIf(!DATABASE_URL)('résultats des modules d’analyse par IA (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let scanId: string
  let server: Server
  let sock: string
  const users: Record<Role | 'agent', number> = { viewer: 0, operator: 0, admin: 0, agent: 0 }
  const ids: Record<string, string> = {}

  function call(path: string, role: Role | 'agent', method = 'GET'): Promise<{ status: number, data: Record<string, unknown> & { data?: { code?: string } } }> {
    return new Promise((resolve, reject) => {
      const req = request({ socketPath: sock, path, method, headers: { 'x-test-role': role } }, (res) => {
        const chunks: Buffer[] = []
        res.on('data', c => chunks.push(c))
        res.on('end', () => {
          let data = {}
          try {
            data = JSON.parse(Buffer.concat(chunks).toString('utf8'))
          }
          catch {
            // corps vide
          }
          resolve({ status: res.statusCode ?? 0, data })
        })
      })
      req.on('error', reject)
      req.end()
    })
  }

  async function ingest(moduleId: string, doc: unknown) {
    const resultDir = join(root, 'results', scanId)
    await mkdir(join(resultDir, moduleId), { recursive: true })
    await writeFile(join(resultDir, moduleId, 'r.sarif'), JSON.stringify(doc))
    return ingestModuleOutputs(db.pool, { scanId, moduleId, resultDir, outputs: { sarif: `${moduleId}/r.sarif` } })
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-ai-findings-'))
    const index = { schema: 1, version: 1, modules: [
      { id: 'fraim', version: '0.8.0', categories: ['sast'], scan: { network: 'ai-relay' } },
      { id: 'bandit', version: '1.0.0', categories: ['sast'] },
    ] }
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify(index))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    users.agent = Number((await createUser(db.pool, { username: 'agent', role: 'operator', password: 'agent-long-password' })).id)
    await db.pool.query(`UPDATE users SET kind = 'agent' WHERE id = $1`, [users.agent])
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('ia', 'Analyse IA', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    scanId = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, job_id, started_at)
       VALUES ($1, 1, 'manual', 50, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', gen_random_uuid(), now())
       RETURNING id`, [projectId],
    )).rows[0]!.id
    for (const m of ['fraim', 'bandit']) {
      await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '1.0.0', 'ok')`, [scanId, m])
    }
    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | 'agent' | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role: role === 'agent' ? 'operator' : role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/findings/:id/ai', aiGet)
    router.post('/api/findings/:id/ai-confirm', aiConfirm)
    app.use(router)
    server = createServer(toNodeListener(app))
    sock = join(root, 'api.sock')
    await new Promise<void>(resolve => server.listen(sock, resolve))
  })

  afterAll(async () => {
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('ingestion : un module relié au relais produit des résultats origin = ai, les autres non', async () => {
    expect((await ingest('fraim', sarif('fraim', [result('ai-sqli', 'app/db.py'), result('ai-ssrf', 'app/http.py')]))).errors).toEqual([])
    expect((await ingest('bandit', sarif('bandit', []))).errors).toEqual([])
    await finalizeScanFindings(db.pool, scanId, { complete: true })
    const { rows } = await db.pool.query<{ id: string, rule_id: string, origin: string }>(`SELECT id, rule_id, origin FROM findings ORDER BY rule_id`)
    expect(rows.map(r => r.origin)).toEqual(['ai', 'ai'])
    ids.sqli = rows[0]!.id
    ids.ssrf = rows[1]!.id
  })

  it('résultats IA : gravité informative tant qu’ils ne sont pas confirmés', async () => {
    const { rows } = await db.pool.query(`SELECT DISTINCT severity, native_severity FROM findings WHERE origin = 'ai'`)
    expect(rows).toEqual([{ severity: 'info', native_severity: 'level:error' }])
  })

  it('origine IA d’après le runner, même si le catalogue ne connaît plus le module', async () => {
    const resultDir = join(root, 'results', scanId)
    await mkdir(join(resultDir, 'retire'), { recursive: true })
    await writeFile(join(resultDir, 'retire', 'r.sarif'), JSON.stringify(sarif('retire', [result('ai-xss', 'app/view.py')])))
    await ingestModuleOutputs(db.pool, { scanId, moduleId: 'retire', resultDir, outputs: { sarif: 'retire/r.sarif' }, aiRelay: true })
    const { rows } = await db.pool.query(`SELECT origin, severity FROM findings WHERE tool = 'retire'`)
    expect(rows).toEqual([{ origin: 'ai', severity: 'info' }])
    await db.pool.query(`DELETE FROM findings WHERE tool = 'retire'`)
  })

  it('verdict : les résultats IA non confirmés n’y entrent pas', async () => {
    const v = await evaluateGate(db.pool, scanId)
    expect(v.counts.critical + v.counts.high).toBe(0)
    expect(v.reasons.filter(r => r.blocking)).toEqual([])
  })

  it('relais : appel journalisé (via relay, module) et modèle lu pour le résultat', async () => {
    const token: RelayToken = { v: 1, purpose: 'scan', module_id: 'fraim', project_id: projectId, scan_id: scanId, expires_at: Math.floor(Date.now() / 1000) + 600 }
    const relay = new Relay({
      db: db.pool,
      tokens: async () => token,
      loadEndpoint: async () => ({ version: 1, enabled: true, url: 'https://ollama.exemple.test:11434', scheme: 'https', host: 'ollama.exemple.test', port: 11434, addresses: ['192.0.2.10'], insecure: false, token: false, ca: false, literal: false, pinned_at: '2026-11-25T08:00:00Z' }),
      clientFor: async () => ({
        version: async () => '0.12.3', tags: async () => [], show: async () => ({}),
        chat: async () => ({ content: '{"ok":true}', bytesSent: 42, durationMs: 3 }),
      }),
      circuit: new CircuitBreaker(),
      selection: async () => ({ tasks: { [RELAY_KEY]: { model: 'qwen-test:7b', digest: 'd'.repeat(64), context: 32768, reason: 'best-balance' } }, embedding: null } as never),
    })
    await relay.chat('Bearer scr_x', { messages: [{ role: 'user', content: 'analyse ceci' }] })
    const { rows } = await db.pool.query(`SELECT via, module_id, project_id, outcome, model FROM ai_calls`)
    expect(rows).toEqual([{ via: 'relay', module_id: 'fraim', project_id: projectId, outcome: 'ok', model: `qwen-test:7b@${'d'.repeat(12)}` }])
    const cached = await db.pool.query(`SELECT count(*)::int AS n FROM ai_cache WHERE kind = $1`, [RELAY_KEY])
    expect(cached.rows[0].n).toBe(1)
    const r = await call(`/api/findings/${ids.sqli}/ai`, 'viewer')
    expect(r.status).toBe(200)
    expect(r.data).toMatchObject({ origin: 'ai', tool: 'fraim', confirmed: false, model: 'qwen-test:7b', digest: 'd'.repeat(12) })
  })

  it('confirmation : viewer refusé, compte agent refusé, operator humain accepté et tracé, pas deux fois', async () => {
    expect((await call(`/api/findings/${ids.sqli}/ai-confirm`, 'viewer', 'POST')).status).toBe(403)
    const agent = await call(`/api/findings/${ids.sqli}/ai-confirm`, 'agent', 'POST')
    expect(agent.status).toBe(403)
    const ok = await call(`/api/findings/${ids.sqli}/ai-confirm`, 'operator', 'POST')
    expect(ok.status).toBe(200)
    expect(ok.data).toMatchObject({ confirmed: true, confirmed_by: 'operator' })
    expect((await call(`/api/findings/${ids.sqli}/ai-confirm`, 'admin', 'POST')).data.data?.code).toBe('E_AI_CONFIRMED')
    const audit = await db.pool.query(`SELECT action, target_id FROM audit_log WHERE action = 'finding.ai-confirm'`)
    expect(audit.rows).toEqual([{ action: 'finding.ai-confirm', target_id: ids.sqli }])
    const st = await db.pool.query(`SELECT status, severity FROM findings WHERE id = $1`, [ids.sqli])
    expect(st.rows[0]).toEqual({ status: 'confirmed', severity: 'high' })
    // Analyse suivante : le résultat confirmé garde sa gravité normalisée.
    await ingest('fraim', sarif('fraim', [result('ai-sqli', 'app/db.py'), result('ai-ssrf', 'app/http.py')]))
    const again = await db.pool.query(`SELECT rule_id, severity FROM findings WHERE origin = 'ai' ORDER BY rule_id`)
    expect(again.rows).toEqual([{ rule_id: 'ai-sqli', severity: 'high' }, { rule_id: 'ai-ssrf', severity: 'info' }])
  })

  it('confirmé : entre dans le verdict suivant ; un résultat non IA ne se confirme pas ainsi', async () => {
    const v = await evaluateGate(db.pool, scanId)
    expect(v.counts.critical + v.counts.high).toBe(1)
    const other = (await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title)
       VALUES ($1, encode(sha256('x'::bytea), 'hex'), 'bandit', 'B1', 'sast', 'low', 't') RETURNING id`, [projectId],
    )).rows[0]!.id
    expect((await call(`/api/findings/${other}/ai-confirm`, 'operator', 'POST')).data.data?.code).toBe('E_NOT_AI')
    expect((await call(`/api/findings/00000000-0000-4000-8000-000000000000/ai-confirm`, 'operator', 'POST')).status).toBe(404)
  })

  it('I24 : accord par module (confirmé contre faux positif)', async () => {
    await db.pool.query(`UPDATE findings SET status = 'false-positive', status_by = $2, status_at = now() WHERE id = $1`, [ids.ssrf, users.operator])
    expect(await aiModuleAgreement(db.pool, 90)).toEqual([{ module: 'fraim', total: 2, confirmed: 1, rejected: 1, pending: 0, rate: 0.5 }])
  })

  it('G20 : une panne de module d’IA (skipped, classe infra ou tool) compte dans la santé, pas un opt-out', async () => {
    await db.pool.query(`UPDATE scan_modules SET status = 'skipped', error_class = 'infra', finished_at = now() WHERE scan_id = $1 AND module_id = 'fraim'`, [scanId])
    await db.pool.query(`UPDATE scan_modules SET status = 'skipped', error_class = 'input', finished_at = now() WHERE scan_id = $1 AND module_id = 'bandit'`, [scanId])
    const health = await toolHealth(db.pool, 7)
    expect(health.map(h => [h.module_id, h.failures])).toEqual([['fraim', 1]])
  })
})
