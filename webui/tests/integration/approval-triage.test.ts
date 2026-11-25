// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Suivi 0.7 (chantier B) : plus d'acceptation d'un risque sans approbation,
// contre un vrai PostgreSQL 16.
// - « accepted » sur un résultat (seul ou en groupe) dépose une demande
//   d'exception de type « finding » (requested_via « console ») : le statut
//   ne change pas et le quality gate bloque toujours.
// - Seule l'approbation par un AUTRE administrateur humain, qui n'est pas
//   l'auteur du commit, pose « accepted » ; la révocation le retire.
// - Les statuts « accepted » déjà en base restent valables (rejeu G11).
// - « false-positive » (et « pas un secret ») : refusé, et audité, pour un
//   compte non humain et pour l'auteur du commit concerné.
// - Règles de tri (F4) : plus de nouvelle règle « accepted », une ancienne ne
//   touche plus rien ; une règle faux positif épargne les commits de son auteur.

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
import { decideException, isoDay, requestFindingAcceptance } from '../../server/findings/exceptions'
import { setFindingStatus } from '../../server/findings/triage'
import { applyTriageRulesOnIngest, createTriageRule } from '../../server/findings/triage-rules'
import { evaluateGate } from '../../server/gates/evaluate'

import statusRoute from '../../server/api/findings/[id]/status.post'
import groupStatusRoute from '../../server/api/findings/[id]/group-status.post'
import secretRoute from '../../server/api/findings/[id]/secret.post'
import decisionRoute from '../../server/api/exceptions/[id]/decision.post'
import revokeRoute from '../../server/api/exceptions/[id].delete'
import ruleCreateRoute from '../../server/api/triage-rules/index.post'

type Who = 'ops' | 'auteur' | 'robot' | 'chef' | 'adjoint'

describe.skipIf(!DATABASE_URL)('approbation obligatoire pour accepter un résultat (F5, J15, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let projectId: string
  let scanId: string
  const users = {} as Record<Who, { id: number, role: 'operator' | 'admin' }>

  async function call(path: string, who: Who, init: { method?: string, json?: unknown } = {}) {
    const headers: Record<string, string> = { 'x-test-user': who }
    if (init.json !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
    const text = await res.text()
    let data: Record<string, unknown> & { data?: { code?: string, reason?: string } } = {}
    try {
      data = JSON.parse(text)
    }
    catch {
      // corps vide
    }
    return { status: res.status, data }
  }

  async function insertFinding(p: Record<string, unknown> = {}): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids, secret_type, correlation_key)
       VALUES ($1, $2, $3, $4, $5, $6, 't', $7, $8, $9, $10) RETURNING id`,
      [projectId, randomBytes(32).toString('hex'), p.tool ?? 'trivy', p.rule_id ?? 'R', p.category ?? 'sca', p.severity ?? 'critical',
        p.path ?? 'src/a.js', p.vuln_ids ?? ['CVE-2026-0002'], p.secret_type ?? null, p.correlation_key ?? null],
    )
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scanId, r.rows[0]!.id])
    return r.rows[0]!.id
  }
  const statusOf = async (id: string) => (await db.pool.query<{ status: string, status_until: string | null, status_by: number | null }>(
    `SELECT status, to_char(status_until, 'YYYY-MM-DD') AS status_until, status_by::int AS status_by FROM findings WHERE id = $1`, [id])).rows[0]!
  /** Résultats d'une gravité que le quality gate compte encore (non écartés par un tri). */
  const counted = async (severity: 'critical' | 'low') => (await evaluateGate(db.pool, scanId)).counts[severity] ?? 0

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-approval-triage-'))
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ schema: 1, version: 1, modules: [
      { id: 'trivy', version: '1', categories: ['sca'] }, { id: 'gitleaks', version: '1', categories: ['secrets'] },
    ] }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    const mk = async (who: Who, role: 'operator' | 'admin', email?: string) => {
      users[who] = { id: Number((await createUser(db.pool, { username: who, role, email, password: `${who}-long-password` })).id), role }
    }
    await mk('ops', 'operator')
    await mk('auteur', 'operator', 'auteur@exemple.test')
    await mk('robot', 'operator')
    await mk('chef', 'admin')
    await mk('adjoint', 'admin', 'adjoint@exemple.test')
    await db.pool.query(`UPDATE users SET kind = 'agent' WHERE username = 'robot'`)
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('appro-tri', 'Approbation tri', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    // L'auteur de la PR analysée est « Auteur@exemple.test » : casse différente de son adresse.
    scanId = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, started_at, finished_at, pull_request)
       VALUES ($1, 1, 'manual', 50, 'main', $2, (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'),
               'done', now(), now(), '{"number": 9, "base_sha": "0000000000000000000000000000000000000000", "author": "Auteur@exemple.test"}') RETURNING id`,
      [projectId, randomBytes(20).toString('hex')],
    )).rows[0]!.id
    await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'trivy', '1', 'ok'), ($1, 'gitleaks', '1', 'ok')`, [scanId])

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const who = getHeader(event, 'x-test-user') as Who | undefined
      if (who) event.context.auth = { user: { id: users[who].id, username: who, displayName: null, role: users[who].role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.post('/api/findings/:id/status', statusRoute)
    router.post('/api/findings/:id/group-status', groupStatusRoute)
    router.post('/api/findings/:id/secret', secretRoute)
    router.post('/api/exceptions/:id/decision', decisionRoute)
    router.delete('/api/exceptions/:id', revokeRoute)
    router.post('/api/triage-rules', ruleCreateRoute)
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

  it('accepter dépose une demande : 202, statut inchangé, gate toujours bloquant, une seule demande en attente', async () => {
    const id = await insertFinding()
    const before = await counted('critical')
    const r = await call(`/api/findings/${id}/status`, 'ops', { method: 'POST', json: { status: 'accepted', reason: 'correctif prévu au prochain sprint', until: isoDay(30) } })
    expect(r.status).toBe(202)
    expect(r.data).toMatchObject({ id, status: 'new' })
    const ex = r.data.exception_request as Record<string, unknown>
    expect(ex).toMatchObject({ kind: 'finding', target: { finding_id: id }, status: 'requested', active: false, requested_via: 'console', requester_is_human: true, expires_on: isoDay(30) })
    expect(ex.commit_authors).toEqual(['Auteur@exemple.test'])
    expect(await statusOf(id)).toMatchObject({ status: 'new', status_until: null })
    expect(await counted('critical')).toBe(before)
    // Aucune ligne « finding.status » : rien n'a été trié ; la demande est auditée.
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'finding.status' AND target_id = $1`, [id])).rowCount).toBe(0)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'exception.request' AND target_id = $1`, [ex.id])).rowCount).toBe(1)
    // Redemander renvoie la demande en attente, sans doublon.
    const again = await call(`/api/findings/${id}/status`, 'ops', { method: 'POST', json: { status: 'accepted', reason: 'autre motif', until: isoDay(10) } })
    expect((again.data.exception_request as { id: string }).id).toBe(ex.id)
    expect((await db.pool.query(`SELECT 1 FROM exceptions WHERE target->>'finding_id' = $1`, [id])).rowCount).toBe(1)
  })

  it('l\'approbation par un autre administrateur pose « accepted » ; le demandeur et l\'auteur du commit ne peuvent pas approuver', async () => {
    const id = await insertFinding()
    // Le demandeur, administrateur, ne peut pas approuver sa propre demande.
    const { request } = await requestFindingAcceptance(db.pool, id, { id: users.chef.id, username: 'chef' }, { reason: 'risque documenté', until: isoDay(20) })
    const own = await call(`/api/exceptions/${request.id}/decision`, 'chef', { method: 'POST', json: { decision: 'approved', reason: 'ok pour moi' } })
    expect(own.status).toBe(403)
    expect(own.data.data).toMatchObject({ code: 'E_DECIDER_NOT_ALLOWED', reason: 'requester' })
    await db.pool.query(`UPDATE scans SET pull_request = jsonb_set(pull_request, '{author}', '"@ADJOINT"') WHERE id = $1`, [scanId])
    const id2 = await insertFinding()
    const { request: r2 } = await requestFindingAcceptance(db.pool, id2, { id: users.ops.id, username: 'ops' }, { reason: 'risque documenté', until: isoDay(20) })
    expect(r2.commit_authors).toEqual(['ADJOINT'])
    const author = await call(`/api/exceptions/${r2.id}/decision`, 'adjoint', { method: 'POST', json: { decision: 'approved', reason: 'mon propre commit' } })
    expect(author.status).toBe(403)
    expect(author.data.data).toMatchObject({ code: 'E_DECIDER_NOT_ALLOWED', reason: 'commit-author' })
    expect(await statusOf(id2)).toMatchObject({ status: 'new' })
    // Un autre administrateur humain approuve : le statut est posé, avec la date et le décideur.
    const ok = await call(`/api/exceptions/${r2.id}/decision`, 'chef', { method: 'POST', json: { decision: 'approved', reason: 'risque accepté en revue' } })
    expect(ok.status).toBe(200)
    expect(await statusOf(id2)).toEqual({ status: 'accepted', status_until: isoDay(20), status_by: users.chef.id })
    const audit = await db.pool.query<{ details: Record<string, unknown> }>(
      `SELECT details FROM audit_log WHERE action = 'finding.status' AND target_id = $1 AND outcome = 'success'`, [id2])
    expect(audit.rows[0]!.details).toMatchObject({ from: 'new', to: 'accepted', until: isoDay(20), exception_id: r2.id })
    await db.pool.query(`UPDATE scans SET pull_request = jsonb_set(pull_request, '{author}', '"Auteur@exemple.test"') WHERE id = $1`, [scanId])
  })

  it('un refus ne pose rien ; la révocation d\'une approbation rend le résultat bloquant', async () => {
    const id = await insertFinding()
    const { request } = await requestFindingAcceptance(db.pool, id, { id: users.ops.id, username: 'ops' }, { reason: 'à voir en comité', until: isoDay(15) })
    await decideException(db.pool, request.id, { decision: 'refused', reason: 'pas acceptable', deciderUserId: users.chef.id })
    expect(await statusOf(id)).toMatchObject({ status: 'new' })
    const { request: again } = await requestFindingAcceptance(db.pool, id, { id: users.ops.id, username: 'ops' }, { reason: 'nouvelle demande', until: isoDay(15) })
    expect(again.id).not.toBe(request.id)
    await decideException(db.pool, again.id, { decision: 'approved', reason: 'accepté', deciderUserId: users.adjoint.id })
    expect(await statusOf(id)).toMatchObject({ status: 'accepted', status_until: isoDay(15) })
    const rev = await call(`/api/exceptions/${again.id}`, 'chef', { method: 'DELETE' })
    expect(rev.status).toBe(200)
    expect(await statusOf(id)).toMatchObject({ status: 'new', status_until: null })
  })

  it('les statuts « accepted » déjà en base restent valables jusqu\'à leur date (rejeu G11)', async () => {
    const id = await insertFinding({ severity: 'low' })
    const before = await counted('low')
    await db.pool.query(`UPDATE findings SET status = 'accepted', status_until = $2::date, status_reason = 'avant le suivi' WHERE id = $1`, [id, isoDay(5)])
    expect(await counted('low')).toBe(before - 1)
    await db.pool.query(`UPDATE findings SET status_until = $2::date WHERE id = $1`, [id, isoDay(-1)])
    expect(await counted('low')).toBe(before)
    await db.pool.query(`UPDATE findings SET status_until = $2::date WHERE id = $1`, [id, isoDay(5)])
    expect(await statusOf(id)).toMatchObject({ status: 'accepted', status_until: isoDay(5) })
  })

  it('setFindingStatus ne pose jamais « accepted » directement', async () => {
    const id = await insertFinding()
    await expect(setFindingStatus(db.pool, id, { status: 'accepted' as never, reason: 'contournement' }, users.chef.id)).rejects.toThrow('E_VALIDATION')
    expect(await statusOf(id)).toMatchObject({ status: 'new' })
  })

  it('groupe : une demande par résultat, aucun statut posé', async () => {
    const key = randomBytes(32).toString('hex')
    const a = await insertFinding({ correlation_key: key })
    const b = await insertFinding({ correlation_key: key, tool: 'osv-scanner' })
    const r = await call(`/api/findings/${a}/group-status`, 'ops', { method: 'POST', json: { status: 'accepted', reason: 'dépendance de recette', until: isoDay(30) } })
    expect(r.status).toBe(202)
    expect(r.data.updated).toEqual([])
    expect((r.data.requested as string[]).length).toBe(2)
    const ex = await db.pool.query<{ fid: string }>(`SELECT target->>'finding_id' AS fid FROM exceptions WHERE id = ANY($1::uuid[]) AND status = 'requested'`, [r.data.requested])
    expect(ex.rows.map(x => x.fid).sort()).toEqual([a, b].sort())
    expect((await statusOf(a)).status).toBe('new')
    expect((await statusOf(b)).status).toBe('new')
  })

  it('faux positif : refusé et audité pour l\'auteur du commit (identifiant ou adresse, sans casse) et pour un compte agent', async () => {
    const id = await insertFinding()
    const byAuthor = await call(`/api/findings/${id}/status`, 'auteur', { method: 'POST', json: { status: 'false-positive', reason: 'mon code est sûr' } })
    expect(byAuthor.status).toBe(403)
    expect(byAuthor.data.data).toMatchObject({ code: 'E_TRIAGE_NOT_ALLOWED', reason: 'commit-author' })
    const byAgent = await call(`/api/findings/${id}/status`, 'robot', { method: 'POST', json: { status: 'false-positive', reason: 'analyse automatique' } })
    expect(byAgent.status).toBe(403)
    expect(byAgent.data.data).toMatchObject({ code: 'E_TRIAGE_NOT_ALLOWED', reason: 'not-human' })
    expect(await statusOf(id)).toMatchObject({ status: 'new' })
    const denied = await db.pool.query<{ details: { reason_code: string } }>(
      `SELECT details FROM audit_log WHERE action = 'finding.status' AND outcome = 'denied' AND target_id = $1 ORDER BY id`, [id])
    expect(denied.rows.map(x => x.details.reason_code)).toEqual(['commit-author', 'not-human'])
    // Une autre personne trie normalement ; confirmer reste permis à l'auteur.
    expect((await call(`/api/findings/${id}/status`, 'auteur', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(200)
    const ok = await call(`/api/findings/${id}/status`, 'ops', { method: 'POST', json: { status: 'false-positive', reason: 'fixture de test' } })
    expect(ok.status).toBe(200)
    expect(await statusOf(id)).toMatchObject({ status: 'false-positive', status_by: users.ops.id })
  })

  it('faux positif d\'un groupe : refusé en entier si l\'auteur du commit trie', async () => {
    const key = randomBytes(32).toString('hex')
    const a = await insertFinding({ correlation_key: key })
    await insertFinding({ correlation_key: key, tool: 'osv-scanner' })
    const r = await call(`/api/findings/${a}/group-status`, 'auteur', { method: 'POST', json: { status: 'false-positive', reason: 'pas concerné' } })
    expect(r.status).toBe(403)
    expect((await statusOf(a)).status).toBe('new')
  })

  it('« pas un secret » : même règle que le faux positif', async () => {
    const id = await insertFinding({ category: 'secrets', tool: 'gitleaks', secret_type: 'generic-api-key', vuln_ids: [] })
    const r = await call(`/api/findings/${id}/secret`, 'auteur', { method: 'POST', json: { state: 'false-positive' } })
    expect(r.status).toBe(403)
    expect(r.data.data).toMatchObject({ code: 'E_TRIAGE_NOT_ALLOWED', reason: 'commit-author' })
    expect((await call(`/api/findings/${id}/secret`, 'robot', { method: 'POST', json: { state: 'false-positive' } })).status).toBe(403)
    expect((await call(`/api/findings/${id}/secret`, 'ops', { method: 'POST', json: { state: 'false-positive' } })).status).toBe(200)
  })

  it('règles de tri : plus de nouvelle « accepted », une ancienne ne touche plus rien, un faux positif épargne les commits de son auteur', async () => {
    const body = { project_id: projectId, match: { tool: 'trivy', rule: 'R-REGLE' }, reason: 'fixtures documentées', expires_on: isoDay(30) }
    const refused = await call('/api/triage-rules', 'chef', { method: 'POST', json: { ...body, action: 'accepted' } })
    expect(refused.status).toBe(400)
    await expect(createTriageRule(db.pool, { ...body, action: 'accepted' }, { id: users.chef.id, username: 'chef', role: 'admin' })).rejects.toThrow('E_VALIDATION')
    // Une règle « accepted » déjà en base (avant le suivi) ne s'applique plus à l'ingestion.
    await db.pool.query(`INSERT INTO triage_rules (project_id, match, action, reason, expires_on, created_by) VALUES ($1, $2, 'accepted', 'ancienne règle', $3::date, $4)`,
      [projectId, JSON.stringify(body.match), isoDay(30), users.chef.id])
    const late = await insertFinding({ rule_id: 'R-REGLE' })
    await applyTriageRulesOnIngest(db.pool, projectId, [late])
    expect((await statusOf(late)).status).toBe('new')
    // Faux positif : la règle de l'auteur du commit n'écarte pas ses propres résultats…
    const mine = await call('/api/triage-rules', 'auteur', { method: 'POST', json: { ...body, action: 'false-positive' } })
    expect(mine.status).toBe(201)
    expect(mine.data.applied).toBe(0)
    expect((await statusOf(late)).status).toBe('new')
    // … ni celle d'un compte agent ; celle d'une autre personne, si.
    const agent = await call('/api/triage-rules', 'robot', { method: 'POST', json: { ...body, action: 'false-positive' } })
    expect(agent.data.applied).toBe(0)
    const other = await call('/api/triage-rules', 'ops', { method: 'POST', json: { ...body, action: 'false-positive' } })
    expect(other.data.applied).toBe(1)
    expect((await statusOf(late)).status).toBe('false-positive')
  })
})
