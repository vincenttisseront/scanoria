// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : simulateur de quality gate (F9, contrat 39) contre un
// vrai PostgreSQL 16. Rejeu identique au verdict réel à règles inchangées ;
// exceptions prises à la date de l'analyse ; effet des règles candidates
// (bloquées, débloquées, releases, règles responsables) ; plancher des verrous
// G8 ; aucune écriture hors de gate_simulations ; tâche de fond pour un long
// historique ; API.

import { randomBytes } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { GateRules } from '#shared/analysis'
import { evaluateGate } from '../../server/gates/evaluate'
import {
  changedRules, effectOf, getSimulation, pendingSimulations, responsibleRules, simulateGate, SimulationError,
  sinceFromDays, startSimulation, SYNC_SIMULATION_SCANS,
} from '../../server/gates/simulate'
import postSimulation from '../../server/api/gates/simulations/index.post'
import getSimulationRoute from '../../server/api/gates/simulations/[id].get'

const DAY = 86_400_000

describe.skipIf(!DATABASE_URL)('simulateur de quality gate (F9, PostgreSQL réel)', () => {
  let db: TestDatabase
  let server: Server
  let base: string
  let projectId: string
  let gateId: string
  let adminId: number
  let viewerId: number
  const scans: Record<string, string> = {}
  let number = 0

  async function insertScan(name: string, p: { daysAgo: number, trigger?: string, verdict: string, tag?: string }): Promise<string> {
    number++
    const finished = new Date(Date.now() - p.daysAgo * DAY).toISOString()
    const id = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, queued_at, started_at, finished_at, verdict, verdict_details)
       VALUES ($1, $2, $3, 50, 'main', $4, (SELECT id FROM profiles WHERE slug = 'rapide'), $5, 'done', $6, $6, $6, $7, '{}') RETURNING id`,
      [projectId, number, p.trigger ?? 'manual', randomBytes(20).toString('hex'), gateId, finished, p.verdict],
    )).rows[0]!.id
    await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'trivy', '1', 'ok')`, [id])
    if (p.tag) {
      await db.pool.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source, scan_id) VALUES ($1, $2, $3, 'pull', $4)`,
        [projectId, p.tag, randomBytes(20).toString('hex'), id])
    }
    scans[name] = id
    return id
  }

  async function insertFinding(scanId: string, p: { severity: string, vuln: string }): Promise<string> {
    const id = (await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids)
       VALUES ($1, $2, 'trivy', $3, 'sca', $4, 't', 'package-lock.json', $5) RETURNING id`,
      [projectId, randomBytes(32).toString('hex'), p.vuln, p.severity, [p.vuln]],
    )).rows[0]!.id
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scanId, id])
    return id
  }

  async function insertException(vuln: string, decidedDaysAgo: number, revokedDaysAgo: number | null = null): Promise<void> {
    const decided = new Date(Date.now() - decidedDaysAgo * DAY).toISOString()
    await db.pool.query(
      `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_at, status, decided_at, decided_by, revoked_at)
       VALUES ($1, 'vuln', $2, 'correctif prévu au prochain sprint', current_date + 60, $3, 'approved', $3, $4, $5)`,
      [projectId, JSON.stringify({ vuln_id: vuln }), decided, adminId,
        revokedDaysAgo === null ? null : new Date(Date.now() - revokedDaysAgo * DAY).toISOString()],
    )
  }

  /** Empreinte de tout ce que le simulateur ne doit jamais modifier. */
  async function snapshot(): Promise<string> {
    const r = await db.pool.query<{ h: string }>(
      `SELECT md5(string_agg(t, '|' ORDER BY t)) AS h FROM (
         SELECT 'scan:' || id || verdict || coalesce(verdict_details::text, '') AS t FROM scans
         UNION ALL SELECT 'finding:' || id || status FROM findings
         UNION ALL SELECT 'exception:' || id || status || coalesce(revoked_at::text, '') FROM exceptions
         UNION ALL SELECT 'audit:' || count(*) FROM audit_log
         UNION ALL SELECT 'vex:' || count(*) FROM vex_statements
         UNION ALL SELECT 'gate:' || id || rules::text FROM gates) x`)
    return r.rows[0]!.h
  }

  async function call(path: string, who: 'admin' | 'viewer', init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-user': who, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    return { status: res.status, data: await res.json() as Record<string, unknown> & { data?: { code?: string } } }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url }))
    adminId = Number((await createUser(db.pool, { username: 'chef', role: 'admin', password: 'chef-long-password' })).id)
    viewerId = Number((await createUser(db.pool, { username: 'lecteur', role: 'viewer', password: 'lecteur-long-password' })).id)
    gateId = (await db.pool.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('simu', 'Simulation', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), $1) RETURNING id`, [gateId],
    )).rows[0]!.id

    // A : vulnérabilité medium, sous le seuil par défaut (high) : réussie.
    await insertFinding(await insertScan('medium', { daysAgo: 10, verdict: 'passed' }), { severity: 'medium', vuln: 'CVE-2026-1001' })
    // B : release v1.0.0, vulnérabilité high couverte par une exception approuvée AVANT l'analyse : réussie.
    await insertException('CVE-2026-1002', 30)
    await insertFinding(await insertScan('release', { daysAgo: 20, trigger: 'release', verdict: 'passed', tag: 'v1.0.0' }), { severity: 'high', vuln: 'CVE-2026-1002' })
    // C : vulnérabilité high, exception approuvée APRÈS l'analyse : bloquée à l'époque.
    await insertFinding(await insertScan('later', { daysAgo: 15, verdict: 'failed' }), { severity: 'high', vuln: 'CVE-2026-1003' })
    await insertException('CVE-2026-1003', 1)
    // D : exception révoquée avant l'analyse : ne s'applique pas.
    await insertException('CVE-2026-1004', 40, 25)
    await insertFinding(await insertScan('revoked', { daysAgo: 5, verdict: 'failed' }), { severity: 'critical', vuln: 'CVE-2026-1004' })
    // E : hors période (200 jours).
    await insertFinding(await insertScan('old', { daysAgo: 200, verdict: 'passed' }), { severity: 'low', vuln: 'CVE-2026-1005' })

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const who = getHeader(event, 'x-test-user')
      const id = who === 'admin' ? adminId : viewerId
      if (who) event.context.auth = { user: { id, username: who, displayName: null, role: who === 'admin' ? 'admin' : 'viewer', locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.post('/api/gates/simulations', postSimulation)
    router.get('/api/gates/simulations/:id', getSimulationRoute)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    await pendingSimulations()
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
  })

  const defaults = () => GateRules.parse({})

  it('règles inchangées : le rejeu donne le verdict réel de chaque analyse, sans effet', async () => {
    const { result } = await simulateGate(db.pool, { gateId, rules: defaults(), since: sinceFromDays(90) })
    expect(result.scans).toMatchObject({ total: 4, blocked: 0, unblocked: 0, unchanged: 4, drift: 0, errors: 0 })
    for (const it of result.items) {
      expect(it.simulated).toBe(it.actual)
      expect(it.replay).toBe(it.actual)
      expect(it.effect).toBe('unchanged')
    }
    expect(result.changed_rules).toEqual([])
    expect(result.items.map(i => i.scan_id)).not.toContain(scans.old)
  })

  it('exceptions prises à la date de l\'analyse, pas à celle du jour', async () => {
    const { result } = await simulateGate(db.pool, { projectId, rules: defaults(), since: sinceFromDays(90) })
    const later = result.items.find(i => i.scan_id === scans.later)!
    expect(later.replay).toBe('failed')
    // Aujourd'hui, l'exception approuvée depuis s'applique : l'évaluation du contrat 6 réussit.
    expect((await evaluateGate(db.pool, scans.later!)).verdict).toBe('passed')
    expect(result.items.find(i => i.scan_id === scans.revoked)!.replay).toBe('failed')
    expect(result.items.find(i => i.scan_id === scans.release)!.replay).toBe('passed')
  })

  it('règles plus strictes : analyses et releases bloquées, règle responsable', async () => {
    const { result } = await simulateGate(db.pool, { gateId, rules: { ...defaults(), vuln_block_from: 'medium' }, since: sinceFromDays(90) })
    expect(result.scans).toMatchObject({ blocked: 1, unblocked: 0, unchanged: 3 })
    expect(result.changed_rules).toEqual(['vuln_block_from'])
    expect(result.by_rule).toEqual([{ rule: 'vuln_block_from', blocked: 1, unblocked: 0 }])
    expect(result.items[0]).toMatchObject({ scan_id: scans.medium, effect: 'blocked', rules: ['vuln_block_from'], replay: 'passed', simulated: 'failed' })
    expect(result.releases).toMatchObject({ total: 1, blocked: 0, unchanged: 1 })
  })

  it('règles plus souples : analyses débloquées, releases comptées', async () => {
    const { result } = await simulateGate(db.pool, { gateId, rules: { ...defaults(), vuln_block_from: null }, since: sinceFromDays(90) })
    expect(result.scans).toMatchObject({ blocked: 0, unblocked: 2, unchanged: 2 })
    expect(result.by_rule).toEqual([{ rule: 'vuln_block_from', blocked: 0, unblocked: 2 }])
    const release = await simulateGate(db.pool, { gateId, rules: { ...defaults(), vuln_block_from: 'low' }, since: sinceFromDays(90) })
    // La release v1.0.0 a son exception : elle reste réussie ; A (medium) se bloque.
    expect(release.result.releases).toMatchObject({ total: 1, blocked: 0 })
    expect(release.result.items.find(i => i.release)).toMatchObject({ tag: 'v1.0.0', effect: 'unchanged' })
  })

  it('n\'écrit que dans gate_simulations', async () => {
    const before = await snapshot()
    const count = Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM gate_simulations')).rows[0]!.n)
    const { id } = await simulateGate(db.pool, { gateId, rules: { ...defaults(), max_secrets: 3, new_code_only: false }, since: sinceFromDays(365), origin: 'ai', createdBy: adminId })
    expect(await snapshot()).toBe(before)
    expect(Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM gate_simulations')).rows[0]!.n)).toBe(count + 1)
    const row = await getSimulation(db.pool, id)
    expect(row).toMatchObject({ status: 'done', origin: 'ai', created_by: 'chef', gate_id: gateId })
    expect(row!.result!.scans.total).toBe(5)
  })

  it('validation : règles invalides, sans portée, gate ou projet inconnu', async () => {
    await expect(simulateGate(db.pool, { gateId, rules: { block_malicious: false }, since: sinceFromDays(90) })).rejects.toBeInstanceOf(SimulationError)
    await expect(simulateGate(db.pool, { rules: defaults(), since: sinceFromDays(90) })).rejects.toThrow('E_VALIDATION')
    await expect(simulateGate(db.pool, { gateId: crypto.randomUUID(), rules: defaults(), since: sinceFromDays(90) })).rejects.toThrow('E_NOT_FOUND')
    await expect(simulateGate(db.pool, { projectId: crypto.randomUUID(), rules: defaults(), since: sinceFromDays(90) })).rejects.toThrow('E_NOT_FOUND')
    await expect(simulateGate(db.pool, { gateId, rules: defaults(), since: new Date(Number.NaN) })).rejects.toThrow('E_VALIDATION')
  })

  it('plancher des verrous (G8) figé dans le plan : une règle candidate plus souple ne s\'applique pas', async () => {
    const id = await insertScan('locked', { daysAgo: 2, verdict: 'failed' })
    await insertFinding(id, { severity: 'high', vuln: 'CVE-2026-1006' })
    await db.pool.query(`UPDATE scans SET plan = $2 WHERE id = $1`, [id, JSON.stringify({ profile: { locks: { gate_floor: { vuln_block_from: 'high' } } } })])
    const { result } = await simulateGate(db.pool, { projectId, rules: { ...defaults(), vuln_block_from: null }, since: sinceFromDays(3) })
    expect(result.items.find(i => i.scan_id === id)).toMatchObject({ replay: 'failed', simulated: 'failed', effect: 'unchanged' })
    await db.pool.query('DELETE FROM scans WHERE id = $1', [id])
  })

  it('fonctions pures : effet, règles responsables, règles changées', () => {
    expect(effectOf('passed', 'inconclusive')).toBe('blocked')
    expect(effectOf('failed', 'passed')).toBe('unblocked')
    expect(effectOf('failed', 'inconclusive')).toBe('unchanged')
    const d = (codes: string[], newCode = true) => ({ rules: { ...defaults(), new_code_only: newCode }, reasons: codes.map(code => ({ code, blocking: true })) }) as never
    expect(responsibleRules(d(['secret']), d(['kev', 'vuln'], false))).toEqual(['kev_blocks', 'max_secrets', 'new_code_only', 'vuln_block_from'])
    expect(changedRules(null, defaults())).toEqual([])
    expect(changedRules(defaults(), { ...defaults(), quarantine_days: 0 })).toEqual(['quarantine_days'])
  })

  it('API : simulation immédiate (201), lecture, validation et rôles', async () => {
    const r = await call('/api/gates/simulations', 'admin', { method: 'POST', json: { gate_id: gateId, rules: { ...defaults(), vuln_block_from: 'medium' }, since_days: 90 } })
    expect(r.status).toBe(201)
    expect(r.data).toMatchObject({ status: 'done', origin: 'manual' })
    const g = await call(`/api/gates/simulations/${r.data.id}`, 'viewer')
    expect(g.status).toBe(200)
    expect((g.data.result as { scans: { blocked: number } }).scans.blocked).toBe(1)
    expect((await call('/api/gates/simulations', 'viewer', { method: 'POST', json: { gate_id: gateId, rules: defaults() } })).status).toBe(403)
    expect((await call('/api/gates/simulations', 'admin', { method: 'POST', json: { rules: defaults() } })).status).toBe(400)
    expect((await call('/api/gates/simulations', 'admin', { method: 'POST', json: { gate_id: gateId, rules: { inconclusive_blocks: false } } })).status).toBe(400)
    expect((await call('/api/gates/simulations', 'admin', { method: 'POST', json: { gate_id: gateId, rules: defaults(), since_days: 0 } })).status).toBe(400)
    expect((await call(`/api/gates/simulations/${crypto.randomUUID()}`, 'viewer')).status).toBe(404)
    expect((await call('/api/gates/simulations/pas-un-uuid', 'viewer')).status).toBe(404)
  })

  it('long historique : réponse « pending » puis résultat en tâche de fond', async () => {
    await db.pool.query(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, queued_at, finished_at, verdict)
       SELECT $1, 1000 + g, 'schedule', 10, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), $2, 'done', now() - interval '1 day', now() - interval '1 day', 'inconclusive'
         FROM generate_series(1, $3::int) g`, [projectId, gateId, SYNC_SIMULATION_SCANS + 5])
    const row = await startSimulation(db.pool, { projectId, rules: defaults(), since: sinceFromDays(30) })
    expect(row.status).toBe('pending')
    expect(row.result).toBeNull()
    await pendingSimulations()
    const done = await getSimulation(db.pool, row.id)
    expect(done!.status).toBe('done')
    expect(done!.result!.scans.total).toBeGreaterThan(SYNC_SIMULATION_SCANS)
    await db.pool.query(`DELETE FROM scans WHERE trigger = 'schedule' AND project_id = $1`, [projectId])
  })
})
