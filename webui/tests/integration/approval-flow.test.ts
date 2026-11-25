// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : circuit des exceptions F5 / J15 (contrat 27) contre un
// vrai PostgreSQL 16. Demande, puis décision par un AUTRE administrateur
// humain ; refus du demandeur, d'un auteur du commit, d'un compte agent ou
// bot, d'un jeton d'API ; H4 et verrous G8 sans exception possible ;
// réévaluation du verdict sans réanalyse et écouteurs ; avis d'échéance.

import { randomBytes } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import {
  clearVerdictListeners, countPendingExceptions, decideException, deciderRefusal, ExceptionError, getException, isoDay,
  listExceptions, listExpiringExceptions, listPendingExceptions, notifyExpiringExceptions, onVerdictChanged, reevaluateProject,
  requestException, revokeException, type ExceptionRequestInput,
} from '../../server/findings/exceptions'
import { exceptionHttpError } from '../../server/findings/exceptions-http'
import { triageTick } from '../../server/findings/tick'

import createRequest from '../../server/api/exceptions/index.post'
import getOne from '../../server/api/exceptions/[id].get'
import revoke from '../../server/api/exceptions/[id].delete'
import pending from '../../server/api/exceptions/pending.get'
import pendingCount from '../../server/api/exceptions/pending-count.get'
import expiring from '../../server/api/exceptions/expiring.get'
import decision from '../../server/api/exceptions/[id]/decision.post'
import ciRequest from '../../server/api/projects/[id]/exception-requests.post'

type Who = 'ops' | 'chef' | 'adjoint' | 'robot' | 'lecteur'

describe.skipIf(!DATABASE_URL)('approbation des exceptions (F5, J15, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let projectId: string
  let scanId: string
  let vulnId: string
  let malId: string
  let secretId: string
  const users = {} as Record<Who, { id: number, role: 'viewer' | 'operator' | 'admin' }>

  async function call(path: string, who: Who | null, init: { method?: string, json?: unknown, token?: boolean } = {}) {
    const headers: Record<string, string> = {}
    if (who) headers['x-test-user'] = who
    if (init.token) headers['x-test-token'] = '1'
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

  const req = (over: Partial<ExceptionRequestInput> = {}): ExceptionRequestInput => ({
    project_id: projectId, kind: 'vuln', target: { vuln_id: 'CVE-2026-0002' }, reason: 'correctif prévu au prochain sprint',
    expires_on: isoDay(30), requested_via: 'console', requester_label: 'ops', requester_is_human: true,
    requester_user_id: users.ops.id, commit_authors: [], ...over,
  })

  async function insertFinding(p: Record<string, unknown>): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids, malicious, secret_type)
       VALUES ($1, $2, $3, $4, $5, $6, 't', $7, $8, $9, $10) RETURNING id`,
      [projectId, randomBytes(32).toString('hex'), p.tool ?? 'trivy', p.rule_id ?? 'R', p.category ?? 'sca', p.severity ?? 'high',
        p.path ?? 'src/a.js', p.vuln_ids ?? [], p.malicious ?? false, p.secret_type ?? null],
    )
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scanId, r.rows[0]!.id])
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-approval-'))
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ schema: 1, version: 1, modules: [
      { id: 'trivy', version: '1', categories: ['sca'] }, { id: 'gitleaks', version: '1', categories: ['secrets'] },
    ] }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    const mk = async (who: Who, role: 'viewer' | 'operator' | 'admin', email?: string) => {
      users[who] = { id: Number((await createUser(db.pool, { username: who, role, email, password: `${who}-long-password` })).id), role }
    }
    await mk('ops', 'operator')
    await mk('chef', 'admin', 'chef@exemple.test')
    await mk('adjoint', 'admin')
    await mk('robot', 'admin')
    await mk('lecteur', 'viewer')
    await db.pool.query(`UPDATE users SET kind = 'agent' WHERE username = 'robot'`)
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('appro', 'Approbation', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    scanId = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, started_at, finished_at, pull_request)
       VALUES ($1, 1, 'manual', 50, 'main', $2, (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'),
               'done', now(), now(), '{"number": 7, "base_sha": "0000000000000000000000000000000000000000", "author": "Auteur-PR"}') RETURNING id`,
      [projectId, randomBytes(20).toString('hex')],
    )).rows[0]!.id
    await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'trivy', '1', 'ok'), ($1, 'gitleaks', '1', 'ok')`, [scanId])
    vulnId = await insertFinding({ vuln_ids: ['CVE-2026-0002'] })
    malId = await insertFinding({ vuln_ids: ['MAL-2026-9'], malicious: true, severity: 'critical' })
    await db.pool.query('UPDATE findings SET status = \'confirmed\' WHERE id = $1', [malId])
    secretId = await insertFinding({ category: 'secrets', tool: 'gitleaks', secret_type: 'generic-api-key', severity: 'high' })
    await db.pool.query('DELETE FROM scan_findings WHERE finding_id = ANY($1::uuid[])', [[malId, secretId]])
    await db.pool.query(`UPDATE scans SET verdict = 'failed', verdict_details = '{}' WHERE id = $1`, [scanId])

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const who = getHeader(event, 'x-test-user') as Who | undefined
      if (who) event.context.auth = { user: { id: users[who].id, username: who, displayName: null, role: users[who].role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
      if (getHeader(event, 'x-test-token')) event.context.apiToken = { id: 't1', projectId, scopes: ['scan:create'], prefix: 'scn_ab12' }
    }))
    const router = createRouter()
    router.post('/api/exceptions', createRequest)
    router.get('/api/exceptions/pending', pending)
    router.get('/api/exceptions/pending-count', pendingCount)
    router.get('/api/exceptions/expiring', expiring)
    router.get('/api/exceptions/:id', getOne)
    router.delete('/api/exceptions/:id', revoke)
    router.post('/api/exceptions/:id/decision', decision)
    router.post('/api/projects/:id/exception-requests', ciRequest)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterEach(() => clearVerdictListeners())

  afterAll(async () => {
    if (server) await new Promise(resolve => server.close(resolve))
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('une demande n\'est pas effective : statut requested, auditée, comptée', async () => {
    const r = await requestException(db.pool, req({ scan_id: scanId, commit_authors: ['@Dev1', 'dev2@exemple.test'] }))
    expect(r).toMatchObject({ status: 'requested', active: false, decided_by: null, requester_is_human: true, requested_via: 'console' })
    expect(r.commit_authors).toEqual(expect.arrayContaining(['Dev1', 'dev2@exemple.test', 'Auteur-PR']))
    expect(await countPendingExceptions(db.pool)).toBe(1)
    expect((await listPendingExceptions(db.pool, projectId)).map(e => e.id)).toEqual([r.id])
    expect((await listExceptions(db.pool, projectId, false)).map(e => e.id)).toContain(r.id)
    const audit = await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'exception.request' AND target_id = $1`, [r.id])
    expect(audit.rowCount).toBe(1)
    await db.pool.query('DELETE FROM exceptions WHERE id = $1', [r.id])
  })

  it('validation : motif, date de fin (366 jours au plus), voie, projet, analyse', async () => {
    await expect(requestException(db.pool, req({ reason: 'x' }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ expires_on: isoDay(367) }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ expires_on: isoDay(-1) }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ requested_via: 'mail' as never }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ requester_label: '  ' }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ project_id: crypto.randomUUID() }))).rejects.toThrow('E_NOT_FOUND')
    await expect(requestException(db.pool, req({ scan_id: crypto.randomUUID() }))).rejects.toThrow('E_NOT_FOUND')
    const ok = await requestException(db.pool, req({ expires_on: isoDay(366), requested_via: 'tool-import', requester_label: 'sonarqube' }))
    expect(ok).toMatchObject({ requested_via: 'tool-import', expires_on: isoDay(366) })
    await db.pool.query('DELETE FROM exceptions WHERE id = $1', [ok.id])
  })

  it('H4 : aucune demande pour un paquet malveillant', async () => {
    await expect(requestException(db.pool, req({ kind: 'vuln', target: { vuln_id: 'MAL-2026-9' } }))).rejects.toThrow('E_MALICIOUS')
    await expect(requestException(db.pool, req({ kind: 'finding', target: { finding_id: malId } }))).rejects.toThrow('E_MALICIOUS')
    await expect(requestException(db.pool, req({ kind: 'rule', target: { rule_id: 'MAL-2026-9' } }))).rejects.toThrow('E_MALICIOUS')
    // Une demande déjà en base devenue malveillante (ligne écrite par l'ancien circuit) n'est pas approuvée.
    const r = await requestException(db.pool, req({ kind: 'rule', target: { rule_id: 'R2' } }))
    await db.pool.query(`UPDATE exceptions SET target = '{"rule_id": "MAL-2026-9"}' WHERE id = $1`, [r.id])
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'ok pour moi', deciderUserId: users.chef.id })).rejects.toThrow('E_MALICIOUS')
    await db.pool.query('DELETE FROM exceptions WHERE id = $1', [r.id])
  })

  it('G8 : un module ou une catégorie exigés, ou un plancher sur les secrets, refusent l\'exception', async () => {
    const prof = (await db.pool.query<{ id: string }>(`SELECT profile_id AS id FROM projects WHERE id = $1`, [projectId])).rows[0]!.id
    await db.pool.query(`UPDATE profiles SET locks = '{"required_modules": ["gitleaks"]}' WHERE id = $1`, [prof])
    await expect(requestException(db.pool, req({ kind: 'module', target: { module_id: 'gitleaks' } }))).rejects.toThrow('E_LOCKED')
    await db.pool.query(`UPDATE profiles SET locks = '{"required_categories": ["sca"]}' WHERE id = $1`, [prof])
    await expect(requestException(db.pool, req({ kind: 'module', target: { module_id: 'trivy' } }))).rejects.toThrow('E_LOCKED')
    const gl = await requestException(db.pool, req({ kind: 'module', target: { module_id: 'gitleaks' } }))
    await db.pool.query(`UPDATE profiles SET locks = '{"gate_floor": {"max_secrets": 0}}' WHERE id = $1`, [prof])
    await expect(requestException(db.pool, req({ kind: 'finding', target: { finding_id: secretId } }))).rejects.toThrow('E_LOCKED')
    // Verrou posé après la demande : l'approbation est refusée aussi.
    await db.pool.query(`UPDATE profiles SET locks = '{"required_modules": ["gitleaks"]}' WHERE id = $1`, [prof])
    await expect(decideException(db.pool, gl.id, { decision: 'approved', reason: 'module en panne', deciderUserId: users.chef.id })).rejects.toThrow('E_LOCKED')
    // Un verrou illisible ne s'applique pas.
    await db.pool.query(`UPDATE profiles SET locks = '{"unknown": 1}' WHERE id = $1`, [prof])
    const ok = await requestException(db.pool, req({ kind: 'finding', target: { finding_id: secretId } }))
    await db.pool.query(`UPDATE profiles SET locks = '{}' WHERE id = $1`, [prof])
    await db.pool.query('DELETE FROM exceptions WHERE id = ANY($1::uuid[])', [[gl.id, ok.id]])
  })

  it('J15 : règles fixes du décideur (pures)', () => {
    const d = { id: 2, username: 'chef', email: 'chef@exemple.test', role: 'admin', kind: 'human', is_active: true }
    const ex = { created_by_id: 1, requester_label: 'ops', commit_authors: [] as string[] }
    expect(deciderRefusal(d, ex)).toBeNull()
    expect(deciderRefusal({ ...d, role: 'operator' }, ex)).toBe('not-admin')
    expect(deciderRefusal({ ...d, kind: 'bot' }, ex)).toBe('not-human')
    expect(deciderRefusal({ ...d, is_active: false }, ex)).toBe('inactive')
    expect(deciderRefusal(d, { ...ex, created_by_id: 2 })).toBe('requester')
    expect(deciderRefusal(d, { ...ex, created_by_id: null, requester_label: '@Chef' })).toBe('requester')
    expect(deciderRefusal(d, { ...ex, commit_authors: ['CHEF@exemple.test'] })).toBe('commit-author')
    expect(deciderRefusal(d, { ...ex, commit_authors: ['@chef'] })).toBe('commit-author')
  })

  it('décision : demandeur, auteur du commit, agent refusés ; contrainte en base ; audit des refus', async () => {
    const r = await requestException(db.pool, req({ requester_user_id: users.chef.id, requester_label: 'chef', commit_authors: ['adjoint'] }))
    const tries: [Who, string][] = [['chef', 'requester'], ['adjoint', 'commit-author'], ['robot', 'not-human'], ['ops', 'not-admin']]
    for (const [who, reason] of tries) {
      const err = await decideException(db.pool, r.id, { decision: 'approved', reason: 'je valide', deciderUserId: users[who].id }).catch(e => e)
      expect(err).toBeInstanceOf(ExceptionError)
      expect(err).toMatchObject({ code: 'E_DECIDER_NOT_ALLOWED', detail: reason })
    }
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'x', deciderUserId: users.chef.id })).rejects.toThrow('E_VALIDATION')
    await expect(decideException(db.pool, r.id, { decision: 'maybe' as never, reason: 'xyz', deciderUserId: users.chef.id })).rejects.toThrow('E_VALIDATION')
    await expect(decideException(db.pool, crypto.randomUUID(), { decision: 'approved', reason: 'xyz', deciderUserId: users.chef.id })).rejects.toThrow('E_NOT_FOUND')
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'xyz', deciderUserId: 999999 })).rejects.toThrow('E_DECIDER_NOT_ALLOWED')
    // La base refuse aussi une auto-décision écrite directement.
    await expect(db.pool.query(`UPDATE exceptions SET status = 'approved', decided_by = created_by, decided_at = now() WHERE id = $1`, [r.id])).rejects.toThrow(/exceptions_not_self_decided/)
    await expect(db.pool.query(`UPDATE exceptions SET status = 'approved' WHERE id = $1`, [r.id])).rejects.toThrow(/exceptions_decision/)
    // Par l'API : refus audité avec sa raison.
    const api = await call(`/api/exceptions/${r.id}/decision`, 'chef', { method: 'POST', json: { decision: 'approved', reason: 'je valide' } })
    expect(api.status).toBe(403)
    expect(api.data.data).toMatchObject({ code: 'E_DECIDER_NOT_ALLOWED', reason: 'requester' })
    const audit = await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'exception.decide' AND outcome = 'denied' AND target_id = $1`, [r.id])
    expect(audit.rowCount).toBeGreaterThan(0)
    // Refus par un autre administrateur : décidé, non effectif, plus décidable.
    const refused = await decideException(db.pool, r.id, { decision: 'refused', reason: 'pas de justification', deciderUserId: users.robot.id }).catch(e => e)
    expect(refused).toMatchObject({ detail: 'not-human' })
    await db.pool.query(`UPDATE users SET kind = 'human' WHERE username = 'robot'`)
    const done = await decideException(db.pool, r.id, { decision: 'refused', reason: 'pas de justification', deciderUserId: users.robot.id })
    await db.pool.query(`UPDATE users SET kind = 'agent' WHERE username = 'robot'`)
    expect(done).toMatchObject({ status: 'refused', active: false, decision_reason: 'pas de justification', decided_by: 'robot' })
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'finalement oui', deciderUserId: users.ops.id })).rejects.toThrow('E_NOT_PENDING')
    expect((await listExceptions(db.pool, projectId, false)).find(e => e.id === r.id)).toBeUndefined()
    expect((await listExceptions(db.pool, projectId, true)).find(e => e.id === r.id)).toMatchObject({ status: 'refused' })
  })

  it('demande échue : plus approuvable', async () => {
    const r = await requestException(db.pool, req({ expires_on: isoDay(1), kind: 'rule', target: { rule_id: 'R9' } }))
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'trop tard', deciderUserId: users.chef.id }, isoDay(5))).rejects.toThrow('E_EXPIRED')
    await revokeException(db.pool, r.id, users.ops.id)
    await expect(decideException(db.pool, r.id, { decision: 'approved', reason: 'retirée', deciderUserId: users.chef.id })).rejects.toThrow('E_NOT_PENDING')
  })

  it('approbation : verdict réévalué sans réanalyse, écouteurs appelés, erreurs d\'écouteur isolées', async () => {
    const before = await reevaluateProject(db.pool, projectId)
    expect(before.map(c => c.scan_id)).toEqual([scanId])
    expect(before[0]!.after).toBe('failed')
    const scansCount = (await db.pool.query('SELECT 1 FROM scans WHERE project_id = $1', [projectId])).rowCount
    const seen: string[] = []
    onVerdictChanged(async () => {
      throw new Error('forge injoignable')
    })
    onVerdictChanged(async (_db, id) => {
      seen.push(id)
    })
    const r = await requestException(db.pool, req())
    const api = await call(`/api/exceptions/${r.id}/decision`, 'adjoint', { method: 'POST', json: { decision: 'approved', reason: 'correctif planifié' } })
    expect(api.status).toBe(200)
    expect(api.data).toMatchObject({ status: 'approved', active: true, decided_by: 'adjoint', reevaluated: [{ scan_id: scanId, before: 'failed', after: 'passed' }] })
    expect(seen).toEqual([scanId])
    expect((await db.pool.query<{ verdict: string }>('SELECT verdict FROM scans WHERE id = $1', [scanId])).rows[0]!.verdict).toBe('passed')
    expect((await db.pool.query('SELECT 1 FROM scans WHERE project_id = $1', [projectId])).rowCount).toBe(scansCount)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'gate.reevaluate' AND target_id = $1`, [projectId])).rowCount).toBeGreaterThan(0)
    // Sans changement, aucun écouteur.
    expect(await reevaluateProject(db.pool, projectId)).toEqual([])
    expect(seen).toHaveLength(1)
    // Évaluation en échec : analyse ignorée, pas d'arrêt.
    expect(await reevaluateProject(db.pool, projectId, async () => {
      throw new Error('boom')
    })).toEqual([])
    // Révocation : le verdict redevient défavorable.
    const rv = await call(`/api/exceptions/${r.id}`, 'ops', { method: 'DELETE' })
    expect(rv.status).toBe(200)
    expect((await db.pool.query<{ verdict: string }>('SELECT verdict FROM scans WHERE id = $1', [scanId])).rows[0]!.verdict).toBe('failed')
    expect(seen).toEqual([scanId, scanId])
  })

  it('API : opérateur demande, lecteur non ; administrateur seul liste et décide ; un jeton ne décide jamais', async () => {
    expect((await call('/api/exceptions', 'lecteur', { method: 'POST', json: { project_id: projectId, kind: 'rule', target: { rule_id: 'R3' }, reason: 'lecteur', expires_on: isoDay(5) } })).status).toBe(403)
    const c = await call('/api/exceptions', 'ops', { method: 'POST', json: { project_id: projectId, kind: 'rule', target: { rule_id: 'R3' }, reason: 'règle bruyante', expires_on: isoDay(5) } })
    expect(c.status).toBe(201)
    expect(c.data).toMatchObject({ status: 'requested', requested_via: 'console', created_by: 'ops' })
    const id = c.data.id as string
    expect((await call(`/api/exceptions/${id}`, 'lecteur')).data).toMatchObject({ id, status: 'requested' })
    expect((await call(`/api/exceptions/${crypto.randomUUID()}`, 'lecteur')).status).toBe(404)
    expect((await call('/api/exceptions/pending', 'ops')).status).toBe(403)
    expect((await call('/api/exceptions/pending-count', 'ops')).data).toMatchObject({ count: 0 })
    expect((await call('/api/exceptions/pending-count', 'chef')).data.count).toBeGreaterThan(0)
    const list = await call(`/api/exceptions/pending?project_id=${projectId}`, 'chef')
    expect((list.data.items as { id: string, cannot_decide: string | null }[]).find(i => i.id === id)).toMatchObject({ cannot_decide: null })
    const robotList = await call('/api/exceptions/pending', 'robot')
    expect((robotList.data.items as { id: string, cannot_decide: string | null }[]).find(i => i.id === id)).toMatchObject({ cannot_decide: 'not-human' })
    expect((await call(`/api/exceptions/${id}/decision`, 'ops', { method: 'POST', json: { decision: 'approved', reason: 'opérateur' } })).status).toBe(403)
    const tok = await call(`/api/exceptions/${id}/decision`, 'chef', { method: 'POST', token: true, json: { decision: 'approved', reason: 'par jeton' } })
    expect(tok.status).toBe(403)
    expect(tok.data.data).toMatchObject({ code: 'E_DECIDER_NOT_ALLOWED', reason: 'not-human' })
    expect((await call(`/api/exceptions/${id}/decision`, 'chef', { method: 'POST', json: { decision: 'approved' } })).status).toBe(400)
    expect((await call('/api/exceptions/x/decision', 'chef', { method: 'POST', json: { decision: 'approved', reason: 'xyz' } })).status).toBe(404)
    const ok = await call(`/api/exceptions/${id}/decision`, 'chef', { method: 'POST', json: { decision: 'refused', reason: 'à corriger plutôt' } })
    expect(ok.data).toMatchObject({ status: 'refused', reevaluated: [] })
    expect((await call(`/api/exceptions/${id}/decision`, 'chef', { method: 'POST', json: { decision: 'approved', reason: 'xyz' } })).status).toBe(409)
  })

  it('CI : un jeton demande (non humain, voie api), jamais pour un autre projet ; H4 en 409', async () => {
    const r = await call(`/api/projects/${projectId}/exception-requests`, null, {
      method: 'POST', token: true,
      json: { kind: 'finding', target: { finding_id: vulnId }, reason: 'faux positif probable, appel inaccessible', expires_on: isoDay(14), scan_id: scanId, commit_authors: ['bot-dev'] },
    })
    expect(r.status).toBe(201)
    expect(r.data).toMatchObject({ status: 'requested', requested_via: 'api', requester_label: 'api-token:scn_ab12', requester_is_human: false, created_by: null })
    expect(r.data.commit_authors).toEqual(expect.arrayContaining(['bot-dev', 'Auteur-PR']))
    const mal = await call(`/api/projects/${projectId}/exception-requests`, null, { method: 'POST', token: true, json: { kind: 'vuln', target: { vuln_id: 'MAL-2026-9' }, reason: 'non', expires_on: isoDay(3) } })
    expect(mal.status).toBe(409)
    expect((await call(`/api/projects/${projectId}/exception-requests`, null, { method: 'POST', json: { kind: 'rule', target: { rule_id: 'x' }, reason: 'sans session', expires_on: isoDay(3) } })).status).toBe(401)
    const session = await call(`/api/projects/${projectId}/exception-requests`, 'ops', { method: 'POST', json: { kind: 'rule', target: { rule_id: 'R4' }, reason: 'par la console', expires_on: isoDay(3) } })
    expect(session.data).toMatchObject({ requested_via: 'console', requester_is_human: true, created_by: 'ops' })
    // Le compte agent demande, mais n'est jamais compté comme humain.
    const agent = await requestException(db.pool, req({ requester_user_id: users.robot.id, requester_label: 'robot', kind: 'rule', target: { rule_id: 'R5' } }))
    expect(agent.requester_is_human).toBe(false)
  })

  it('échéance : avis unique à 14 jours, bandeau, tâche périodique', async () => {
    const r = await requestException(db.pool, req({ kind: 'rule', target: { rule_id: 'R6' }, expires_on: isoDay(10) }))
    await decideException(db.pool, r.id, { decision: 'approved', reason: 'en attendant la montée', deciderUserId: users.chef.id })
    expect((await listExpiringExceptions(db.pool, projectId)).map(e => e.id)).toContain(r.id)
    expect((await call(`/api/exceptions/expiring?project_id=${projectId}`, 'lecteur')).data.items).toEqual(expect.arrayContaining([expect.objectContaining({ id: r.id, expiring_soon: true })]))
    expect(await notifyExpiringExceptions(db.pool)).toBeGreaterThan(0)
    expect(await notifyExpiringExceptions(db.pool)).toBe(0)
    expect((await getException(db.pool, r.id))!.expiry_notified_at).toBeTruthy()
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'exception.expiry-notice' AND target_id = $1`, [r.id])).rowCount).toBe(1)
    await db.pool.query(`UPDATE exceptions SET expires_on = current_date - 1 WHERE id = $1`, [r.id])
    await expect(triageTick(db.pool)).resolves.not.toThrow()
    expect((await getException(db.pool, r.id))!.expired).toBe(true)
  })

  it('erreurs HTTP à code stable', () => {
    const codes = ['E_NOT_FOUND', 'E_MALICIOUS', 'E_LOCKED', 'E_NOT_PENDING', 'E_EXPIRED', 'E_DECIDER_NOT_ALLOWED', 'E_VALIDATION'] as const
    expect(codes.map(c => (exceptionHttpError(new ExceptionError(c, 'x')) as { statusCode: number }).statusCode)).toEqual([404, 409, 409, 409, 409, 403, 400])
    const other = new Error('autre')
    expect(exceptionHttpError(other)).toBe(other)
  })
})
