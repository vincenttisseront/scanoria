// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : règles de tri en masse (F4) contre un vrai PostgreSQL 16.
// Simulation sans écriture, application à l'enregistrement et à l'ingestion,
// droits (règles globales réservées à l'admin, plus de nouvelle règle « accepted »), H4,
// révocation et échéance qui remettent les résultats à « nouveau », audit,
// propositions issues du pré-tri IA (I3) sans enregistrement automatique.

import { randomBytes } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { isoDay } from '../../server/findings/exceptions'
import {
  applyTriageRulesOnIngest, commonDirGlob, compileMatch, createTriageRule, expireTriageRules, getTriageRule, listTriageRules,
  proposeTriageRules, revokeTriageRule, ruleMatchSchema, simulateTriageRule, triageRuleSchema, TriageRuleError, AUDIT_DETAIL_MAX,
} from '../../server/findings/triage-rules'
import { setFindingStatus } from '../../server/findings/triage'
import type { Role } from '#shared/schemas'

import listRoute from '../../server/api/triage-rules/index.get'
import simulateRoute from '../../server/api/triage-rules/simulate.post'
import createRoute from '../../server/api/triage-rules/index.post'
import revokeRoute from '../../server/api/triage-rules/[id].delete'
import proposalsRoute from '../../server/api/triage-rules/proposals.get'

describe('règles de tri : correspondance (pure)', () => {
  it('chemin, outil, règle, gravité ; filtre vide refusé ; jokers bornés', () => {
    const m = compileMatch({ path: 'tests/**', tool: 'trivy', severity: ['low', 'medium'] })
    expect(m({ path: 'tests/a/b.js', tool: 'trivy', rule_id: 'x', severity: 'low' })).toBe(true)
    expect(m({ path: './tests/b.js', tool: 'trivy', rule_id: 'x', severity: 'medium' })).toBe(true)
    expect(m({ path: 'src/tests/b.js', tool: 'trivy', rule_id: 'x', severity: 'low' })).toBe(false)
    expect(m({ path: 'tests/b.js', tool: 'gitleaks', rule_id: 'x', severity: 'low' })).toBe(false)
    expect(m({ path: 'tests/b.js', tool: 'trivy', rule_id: 'x', severity: 'high' })).toBe(false)
    expect(m({ path: null, tool: 'trivy', rule_id: 'x', severity: 'low' })).toBe(false)
    expect(compileMatch({ rule: 'R1' })({ path: null, tool: 'a', rule_id: 'R1', severity: 'info' })).toBe(true)
    expect(ruleMatchSchema.safeParse({}).success).toBe(false)
    expect(ruleMatchSchema.safeParse({ path: '*a*b*c*d*e*f*g*h*i' }).success).toBe(false)
    expect(ruleMatchSchema.safeParse({ path: 'a\u0000b' }).success).toBe(false)
    expect(ruleMatchSchema.safeParse({ tool: '../x' }).success).toBe(false)
    expect(triageRuleSchema.safeParse({ project_id: null, match: { rule: 'x' }, action: 'fixed', reason: 'abc', expires_on: isoDay(3) }).success).toBe(false)
  })

  it('dossier commun en glob', () => {
    expect(commonDirGlob(['tests/a/x.js', 'tests/a/y.js', 'tests/b/z.js'])).toBe('tests/**')
    expect(commonDirGlob(['tests/a/x.js', 'tests/a/y.js'])).toBe('tests/a/**')
    expect(commonDirGlob(['x.js', 'tests/y.js'])).toBeNull()
    expect(commonDirGlob(['a/x.js', 'b/y.js'])).toBeNull()
    expect(commonDirGlob(['a/x.js', null])).toBeNull()
    expect(commonDirGlob(['a*/x.js', 'a*/y.js'])).toBeNull()
  })
})

describe.skipIf(!DATABASE_URL)('règles de tri (F4, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let projectId: string
  let otherId: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }
  const op = () => ({ id: users.operator, username: 'operator', role: 'operator' })
  const admin = () => ({ id: users.admin, username: 'admin', role: 'admin' })

  async function call(path: string, role: Role | null, init: { method?: string, json?: unknown } = {}) {
    const headers: Record<string, string> = {}
    if (role) headers['x-test-role'] = role
    if (init.json !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
    const text = await res.text()
    let data: Record<string, unknown> = {}
    try {
      data = JSON.parse(text)
    }
    catch {
      // corps vide
    }
    return { status: res.status, data }
  }

  async function finding(project: string, v: Record<string, unknown> = {}): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, malicious, secret_type, status)
       VALUES ($1, $2, $3, $4, $5, $6, 't', $7, $8, $9, $10) RETURNING id`,
      [project, randomBytes(32).toString('hex'), v.tool ?? 'trivy', v.rule_id ?? 'R1', v.category ?? 'sca', v.severity ?? 'low',
        v.path ?? 'tests/a.js', v.malicious ?? false, v.secret_type ?? null, v.status ?? 'new'],
    )
    return r.rows[0]!.id
  }
  const status = async (id: string) => (await db.pool.query<{ status: string, triage_rule_id: string | null, status_until: string | null }>(
    `SELECT status, triage_rule_id, to_char(status_until, 'YYYY-MM-DD') AS status_until FROM findings WHERE id = $1`, [id])).rows[0]!

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-triage-'))
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ schema: 1, version: 1, modules: [{ id: 'trivy', version: '1', categories: ['sca'] }] }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    const mk = async (slug: string) => (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ($1, $1, 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`, [slug],
    )).rows[0]!.id
    projectId = await mk('tri')
    otherId = await mk('autre')

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/triage-rules', listRoute)
    router.post('/api/triage-rules/simulate', simulateRoute)
    router.get('/api/triage-rules/proposals', proposalsRoute)
    router.post('/api/triage-rules', createRoute)
    router.delete('/api/triage-rules/:id', revokeRoute)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('simulation : rien n\'est écrit ; jamais un malveillant ni un résultat déjà trié', async () => {
    const a = await finding(projectId)
    const b = await finding(projectId, { path: 'tests/deep/b.js' })
    const mal = await finding(projectId, { malicious: true })
    const triaged = await finding(projectId, { status: 'confirmed' })
    await finding(projectId, { path: 'src/c.js' })
    await finding(otherId)
    const input = { project_id: projectId, match: { path: 'tests/**' }, action: 'false-positive' as const, reason: 'jeux de test', expires_on: isoDay(90) }
    const sim = await simulateTriageRule(db.pool, input)
    expect(sim.total).toBe(2)
    expect(sim.items.map(i => i.id).sort()).toEqual([a, b].sort())
    expect(sim.projects).toEqual([{ project_id: projectId, project_slug: 'tri', count: 2 }])
    expect(sim.truncated).toBe(false)
    expect((await status(a)).status).toBe('new')
    expect((await status(mal)).status).toBe('new')
    expect((await status(triaged)).status).toBe('confirmed')
    await expect(simulateTriageRule(db.pool, { ...input, expires_on: isoDay(400) })).rejects.toThrow(TriageRuleError)
    await expect(simulateTriageRule(db.pool, { ...input, expires_on: isoDay(-1) })).rejects.toThrow('E_VALIDATION')
    // Toute l'appliance : les deux projets.
    expect((await simulateTriageRule(db.pool, { ...input, project_id: null })).projects).toHaveLength(2)
  })

  it('enregistrement : appliqué, audité, triage_rule_id posé ; droits ; projet inconnu', async () => {
    const input = { project_id: projectId, match: { path: 'tests/**' }, action: 'false-positive' as const, reason: 'jeux de test', expires_on: isoDay(90) }
    await expect(createTriageRule(db.pool, { ...input, action: 'accepted' }, op())).rejects.toThrow('E_VALIDATION')
    await expect(createTriageRule(db.pool, { ...input, project_id: null }, op())).rejects.toThrow('E_FORBIDDEN')
    await expect(createTriageRule(db.pool, { ...input, project_id: crypto.randomUUID() }, op())).rejects.toThrow('E_NOT_FOUND')
    const { rule, applied } = await createTriageRule(db.pool, input, op())
    expect(applied).toBe(2)
    expect(rule).toMatchObject({ project_slug: 'tri', action: 'false-positive', applied_count: 2, created_by: 'operator', active: true })
    const touched = await db.pool.query<{ id: string }>('SELECT id FROM findings WHERE triage_rule_id = $1', [rule.id])
    expect(touched.rowCount).toBe(2)
    expect((await status(touched.rows[0]!.id)).status).toBe('false-positive')
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'finding.triage-rule'`)).rowCount).toBe(2)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'triage-rule.create' AND target_id = $1`, [rule.id])).rowCount).toBe(1)
    expect((await listTriageRules(db.pool, { projectId })).map(r => r.id)).toContain(rule.id)
    // Un tri humain ultérieur efface le lien avec la règle et n'est jamais écrasé par la révocation.
    await setFindingStatus(db.pool, touched.rows[0]!.id, { status: 'confirmed' }, users.operator)
    expect(await status(touched.rows[0]!.id)).toMatchObject({ status: 'confirmed', triage_rule_id: null })
    const rv = await revokeTriageRule(db.pool, rule.id, op())
    expect(rv.reverted).toBe(1)
    expect(rv.rule).toMatchObject({ active: false, revoked_by: 'operator' })
    expect((await status(touched.rows[0]!.id)).status).toBe('confirmed')
    expect((await status(touched.rows[1]!.id)).status).toBe('new')
    expect((await revokeTriageRule(db.pool, rule.id, op())).reverted).toBe(0)
    await expect(revokeTriageRule(db.pool, crypto.randomUUID(), op())).rejects.toThrow('E_NOT_FOUND')
    expect((await listTriageRules(db.pool, { projectId })).map(r => r.id)).not.toContain(rule.id)
    expect((await listTriageRules(db.pool, { projectId, all: true })).map(r => r.id)).toContain(rule.id)
  })

  it('accepted : refusé même à un administrateur (F5, J15) ; une ancienne règle ne touche plus rien, révocable par un admin', async () => {
    const other = await finding(projectId, { tool: 'gitleaks', rule_id: 'generic', path: 'fixtures/l.env' })
    const input = { project_id: projectId, match: { tool: 'gitleaks', rule: 'generic' }, action: 'accepted' as const, reason: 'fixtures documentées', expires_on: isoDay(30) }
    await expect(createTriageRule(db.pool, input, admin())).rejects.toThrow('E_VALIDATION')
    await expect(simulateTriageRule(db.pool, input)).rejects.toThrow('E_VALIDATION')
    // Règle « accepted » enregistrée avant le suivi : lisible, sans effet à l'ingestion.
    const legacy = (await db.pool.query<{ id: string }>(
      `INSERT INTO triage_rules (project_id, match, action, reason, expires_on, created_by) VALUES ($1, $2, 'accepted', 'ancienne', $3::date, $4) RETURNING id`,
      [projectId, JSON.stringify(input.match), isoDay(30), admin().id])).rows[0]!.id
    expect(await applyTriageRulesOnIngest(db.pool, projectId, [other])).toBe(0)
    expect((await status(other)).status).toBe('new')
    await expect(revokeTriageRule(db.pool, legacy, op())).rejects.toThrow('E_FORBIDDEN')
    await revokeTriageRule(db.pool, legacy, admin())
  })

  it('ingestion : règles actives du projet puis de l\'appliance, la plus ancienne d\'abord ; règle illisible ignorée', async () => {
    const r1 = (await createTriageRule(db.pool, { project_id: projectId, match: { rule: 'ING' }, action: 'confirmed', reason: 'règle connue', expires_on: isoDay(10) }, op())).rule
    const r2 = (await createTriageRule(db.pool, { project_id: null, match: { rule: 'ING' }, action: 'false-positive', reason: 'globale', expires_on: isoDay(10) }, admin())).rule
    await db.pool.query(`INSERT INTO triage_rules (project_id, match, action, reason, expires_on) VALUES ($1, '{"bad": 1}', 'confirmed', 'illisible', current_date + 5)`, [projectId])
    const f1 = await finding(projectId, { rule_id: 'ING' })
    const f2 = await finding(otherId, { rule_id: 'ING' })
    const f3 = await finding(projectId, { rule_id: 'AUTRE' })
    expect(await applyTriageRulesOnIngest(db.pool, projectId, [f1, f3])).toBe(1)
    expect(await status(f1)).toMatchObject({ status: 'confirmed', triage_rule_id: r1.id })
    expect((await status(f3)).status).toBe('new')
    expect(await applyTriageRulesOnIngest(db.pool, otherId, [f2])).toBe(1)
    expect(await status(f2)).toMatchObject({ status: 'false-positive', triage_rule_id: r2.id })
    expect(await applyTriageRulesOnIngest(db.pool, projectId, [])).toBe(0)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'finding.triage-rule' AND details->>'via' = 'ingest'`)).rowCount).toBe(2)

    // Échéance : effets annulés une fois, audités.
    await db.pool.query('UPDATE triage_rules SET expires_on = current_date - 1 WHERE id = ANY($1::uuid[])', [[r1.id, r2.id]])
    expect(await expireTriageRules(db.pool)).toBeGreaterThanOrEqual(2)
    expect((await status(f1)).status).toBe('new')
    expect((await status(f2)).status).toBe('new')
    expect(await expireTriageRules(db.pool)).toBe(0)
    expect((await getTriageRule(db.pool, r1.id))!.active).toBe(false)
  })

  it('audit en synthèse au-delà du seuil', async () => {
    const ids: string[] = []
    const values: string[] = []
    for (let i = 0; i <= AUDIT_DETAIL_MAX; i++) values.push(`('${projectId}', '${randomBytes(32).toString('hex')}', 'trivy', 'BULK', 'sca', 'low', 't', 'bulk/${i}.js')`)
    const r = await db.pool.query<{ id: string }>(`INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path) VALUES ${values.join(', ')} RETURNING id`)
    ids.push(...r.rows.map(x => x.id))
    const { rule, applied } = await createTriageRule(db.pool, { project_id: projectId, match: { rule: 'BULK' }, action: 'false-positive', reason: 'génération', expires_on: isoDay(5) }, op())
    expect(applied).toBe(ids.length)
    const a = await db.pool.query<{ details: { count: number, summarized: boolean } }>(`SELECT details FROM audit_log WHERE action = 'triage-rule.apply' AND target_id = $1`, [rule.id])
    expect(a.rows[0]!.details).toMatchObject({ count: ids.length, summarized: true })
    await revokeTriageRule(db.pool, rule.id, op())
  })

  it('propositions I3 : groupes d\'au moins trois, raison citée, jamais pour « aucun envoi à l\'IA »', async () => {
    const mkAi = async (fid: string, suggestion: string, kind: string, cited = true) => db.pool.query(
      `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, status, output, finished_at) VALUES ('triage-finding', $1, 'finding', $2, 'done', $3, now())`,
      [projectId, fid, JSON.stringify({ suggestion, reasons: [{ kind, explanation: 'valeur factice dans un test', cited }] })],
    )
    const fs: string[] = []
    for (const p of ['spec/a/x.js', 'spec/a/y.js', 'spec/b/z.js']) {
      const id = await finding(projectId, { rule_id: 'PROP', path: p })
      fs.push(id)
      await mkAi(id, 'likely-false-positive', 'test-code')
    }
    const weak = await finding(projectId, { rule_id: 'PROP2', path: 'x/a.js' })
    await mkAi(weak, 'likely-false-positive', 'test-code')
    const uncited = await finding(projectId, { rule_id: 'PROP3', path: 'x/a.js' })
    await mkAi(uncited, 'likely-false-positive', 'test-code', false)
    const props = await proposeTriageRules(db.pool, projectId)
    expect(props).toHaveLength(1)
    expect(props[0]).toMatchObject({ match: { tool: 'trivy', rule: 'PROP', path: 'spec/**' }, action: 'false-positive', reason_kind: 'test-code', count: 3, reason: 'valeur factice dans un test' })
    expect(props[0]!.finding_ids.sort()).toEqual(fs.sort())
    // Rien n'est enregistré automatiquement.
    expect((await listTriageRules(db.pool, { projectId })).find(r => r.match.rule === 'PROP')).toBeUndefined()
    await db.pool.query('UPDATE projects SET ai_opt_out = true WHERE id = $1', [projectId])
    expect(await proposeTriageRules(db.pool, projectId)).toEqual([])
    await db.pool.query('UPDATE projects SET ai_opt_out = false WHERE id = $1', [projectId])
  })

  it('API : lecteur lit, opérateur simule et crée, accepted refusé, admin pour une règle globale ; sans connecteur, pas de propositions', async () => {
    const body = { project_id: projectId, match: { rule: 'API' }, action: 'false-positive', reason: 'bruit connu', expires_on: isoDay(20) }
    await finding(projectId, { rule_id: 'API' })
    expect((await call(`/api/triage-rules?project_id=${projectId}`, null)).status).toBe(401)
    expect((await call(`/api/triage-rules?project_id=${projectId}`, 'viewer')).status).toBe(200)
    expect((await call('/api/triage-rules/simulate', 'viewer', { method: 'POST', json: body })).status).toBe(403)
    const sim = await call('/api/triage-rules/simulate', 'operator', { method: 'POST', json: body })
    expect(sim.data).toMatchObject({ total: 1 })
    expect((await call('/api/triage-rules/simulate', 'operator', { method: 'POST', json: { ...body, match: {} } })).status).toBe(400)
    expect((await call('/api/triage-rules', 'admin', { method: 'POST', json: { ...body, action: 'accepted' } })).status).toBe(400)
    expect((await call('/api/triage-rules', 'operator', { method: 'POST', json: { ...body, project_id: null } })).status).toBe(403)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'triage-rule.create' AND outcome = 'denied'`)).rowCount).toBe(1)
    expect((await call('/api/triage-rules', 'operator', { method: 'POST', json: { ...body, expires_on: isoDay(500) } })).status).toBe(400)
    expect((await call('/api/triage-rules', 'operator', { method: 'POST', json: { ...body, project_id: crypto.randomUUID() } })).status).toBe(404)
    const c = await call('/api/triage-rules', 'operator', { method: 'POST', json: body })
    expect(c.status).toBe(201)
    expect(c.data).toMatchObject({ applied: 1 })
    const id = (c.data.rule as { id: string }).id
    expect((await call(`/api/triage-rules/${id}`, 'viewer', { method: 'DELETE' })).status).toBe(403)
    const d = await call(`/api/triage-rules/${id}`, 'operator', { method: 'DELETE' })
    expect(d.data).toMatchObject({ reverted: 1 })
    expect((await call(`/api/triage-rules/${crypto.randomUUID()}`, 'operator', { method: 'DELETE' })).status).toBe(404)
    expect((await call('/api/triage-rules/x', 'operator', { method: 'DELETE' })).status).toBe(404)
    expect((await call(`/api/triage-rules/proposals?project_id=${projectId}`, 'operator')).data).toEqual({ enabled: false, items: [] })
  })
})
