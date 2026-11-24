// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D : API des résultats, des exceptions et des gravités, servie par
// h3 dans le processus contre un vrai PostgreSQL 16. La session est simulée
// (en-tête de test) : le contrôle commun est couvert par api.test.ts.

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
import type { Role } from '#shared/schemas'

import listFindings from '../../server/api/findings/index.get'
import summary from '../../server/api/findings/summary.get'
import getFinding from '../../server/api/findings/[id].get'
import setStatus from '../../server/api/findings/[id]/status.post'
import setSecret from '../../server/api/findings/[id]/secret.post'
import listExceptions from '../../server/api/exceptions/index.get'
import createException from '../../server/api/exceptions/index.post'
import revokeException from '../../server/api/exceptions/[id].delete'
import listMaps from '../../server/api/severity-maps/index.get'
import patchMap from '../../server/api/severity-maps/index.patch'

describe.skipIf(!DATABASE_URL)('API des résultats (h3, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }
  let projectId: string
  const ids: Record<string, string> = {}

  async function call(path: string, role: Role | null, init: { method?: string, json?: unknown } = {}) {
    const headers: Record<string, string> = {}
    if (role) headers['x-test-role'] = role
    if (init.json !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
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

  async function finding(values: Record<string, unknown>): Promise<string> {
    const row: Record<string, unknown> = { tool: 'trivy', rule_id: 'r', category: 'sca', severity: 'high', title: 't', ...values }
    const cols = Object.keys(row)
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, ${cols.join(', ')})
       VALUES ($1, encode(sha256(gen_random_uuid()::text::bytea), 'hex'), ${cols.map((_, i) => `$${i + 2}`).join(', ')}) RETURNING id`,
      [projectId, ...cols.map(c => row[c])],
    )
    return r.rows[0]!.id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-findings-api-'))
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ schema: 1, version: 1, modules: [{ id: 'trivy', version: '1', categories: ['sca'], scan: { severity_map: { error: 'critical' } } }] }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = (await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id
    }
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('api', 'API <b>', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    ids.vuln = await finding({ vuln_ids: ['CVE-2021-44906'], package: JSON.stringify({ ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: ['1.2.6'] }) })
    ids.mal = await finding({ vuln_ids: ['MAL-2025-1'], malicious: true, severity: 'critical' })
    ids.secret = await finding({ category: 'secrets', secret_type: 'generic-api-key', secret_state: 'to-revoke', tool: 'gitleaks' })
    await db.pool.query(`INSERT INTO severity_maps (module_id, native, severity) VALUES ('trivy', 'level:error', 'critical')`)

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/findings', listFindings)
    router.get('/api/findings/summary', summary)
    router.get('/api/findings/:id', getFinding)
    router.post('/api/findings/:id/status', setStatus)
    router.post('/api/findings/:id/secret', setSecret)
    router.get('/api/exceptions', listExceptions)
    router.post('/api/exceptions', createException)
    router.delete('/api/exceptions/:id', revokeException)
    router.get('/api/severity-maps', listMaps)
    router.patch('/api/severity-maps', patchMap)
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

  it('lecture : authentification exigée, filtres validés, pagination', async () => {
    expect((await call('/api/findings', null)).status).toBe(401)
    const all = await call('/api/findings?limit=2', 'viewer')
    expect(all.status).toBe(200)
    expect(all.data.total).toBe(3)
    expect((all.data.items as { malicious: boolean }[])[0]!.malicious).toBe(true)
    expect((all.data.items as unknown[]).length).toBe(2)
    const filtered = await call(`/api/findings?project_id=${projectId}&severity=high,critical&status=new&secret=false&malicious=false&q=minimist`, 'viewer')
    expect(filtered.data.total).toBe(1)
    expect((await call('/api/findings?severity=bad', 'viewer')).status).toBe(400)
    expect((await call('/api/findings?unknown=1', 'viewer')).status).toBe(400)
    expect((await call('/api/findings?q=%25', 'viewer')).data.total).toBe(0)
    const one = await call(`/api/findings/${ids.vuln}`, 'viewer')
    expect(one.data).toMatchObject({ id: ids.vuln, project_name: 'API <b>', scans: [] })
    expect((await call('/api/findings/not-a-uuid', 'viewer')).status).toBe(404)
    expect((await call(`/api/findings/${crypto.randomUUID()}`, 'viewer')).status).toBe(404)
    const sum = await call('/api/findings/summary', 'viewer')
    expect((sum.data.projects as unknown[])[0]).toMatchObject({ open: 3, critical: 1, high: 2, secrets_to_revoke: 1, malicious: 1 })
  })

  it('tri : opérateur seulement, motif et date de fin pour une acceptation, audité', async () => {
    expect((await call(`/api/findings/${ids.vuln}/status`, 'viewer', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(403)
    expect((await call(`/api/findings/${ids.vuln}/status`, 'operator', { method: 'POST', json: { status: 'accepted', reason: 'x' } })).status).toBe(400)
    expect((await call(`/api/findings/${ids.vuln}/status`, 'operator', { method: 'POST', json: { status: 'accepted', reason: 'correctif prévu', until: isoDay(400) } })).status).toBe(400)
    expect((await call(`/api/findings/${ids.vuln}/status`, 'operator', { method: 'POST', json: { status: 'fixed' } })).status).toBe(400)
    const ok = await call(`/api/findings/${ids.vuln}/status`, 'operator', { method: 'POST', json: { status: 'accepted', reason: 'correctif prévu', until: isoDay(20) } })
    expect(ok.status).toBe(200)
    expect(ok.data).toMatchObject({ status: 'accepted', status_by: 'operator', status_reason: 'correctif prévu' })
    expect((await call(`/api/findings/${crypto.randomUUID()}/status`, 'operator', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(404)
    expect((await call('/api/findings/x/status', 'operator', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(404)
    const audit = await db.pool.query(`SELECT details FROM audit_log WHERE action = 'finding.status' AND outcome = 'success'`)
    expect(audit.rows[0].details).toMatchObject({ from: 'new', to: 'accepted', until: isoDay(20) })
  })

  it('H4 : refus 409 E_MALICIOUS, audité comme refusé', async () => {
    const res = await call(`/api/findings/${ids.mal}/status`, 'operator', { method: 'POST', json: { status: 'false-positive', reason: 'pas nous' } })
    expect(res.status).toBe(409)
    expect(res.data.data?.code).toBe('E_MALICIOUS')
    const ex = await call('/api/exceptions', 'operator', { method: 'POST', json: { project_id: projectId, kind: 'vuln', target: { vuln_id: 'MAL-2025-1' }, reason: 'non', expires_on: isoDay(5) } })
    expect(ex.status).toBe(409)
    const denied = await db.pool.query(`SELECT count(*)::int AS n FROM audit_log WHERE outcome = 'denied'`)
    expect(denied.rows[0].n).toBe(2)
  })

  it('secrets (F7) : révoqué avec auteur ; refus pour un résultat qui n\'est pas un secret', async () => {
    const res = await call(`/api/findings/${ids.secret}/secret`, 'operator', { method: 'POST', json: { state: 'revoked' } })
    expect(res.data).toMatchObject({ secret_state: 'revoked', secret_state_by: 'operator' })
    expect((await call(`/api/findings/${ids.vuln}/secret`, 'operator', { method: 'POST', json: { state: 'revoked' } })).data.data?.code).toBe('E_NOT_SECRET')
    expect((await call(`/api/findings/${crypto.randomUUID()}/secret`, 'operator', { method: 'POST', json: { state: 'revoked' } })).status).toBe(404)
    expect((await call('/api/findings/x/secret', 'operator', { method: 'POST', json: { state: 'revoked' } })).status).toBe(404)
    expect((await call(`/api/findings/${ids.secret}/secret`, 'viewer', { method: 'POST', json: { state: 'revoked' } })).status).toBe(403)
  })

  it('exceptions : création validée par type, liste, révocation', async () => {
    expect((await call('/api/exceptions', 'operator', { method: 'POST', json: { project_id: projectId, kind: 'path', target: { rule_id: 'x' }, reason: 'mauvais type', expires_on: isoDay(5) } })).status).toBe(400)
    expect((await call('/api/exceptions', 'operator', { method: 'POST', json: { project_id: projectId, kind: 'rule', target: { rule_id: 'x' }, reason: 'trop loin', expires_on: isoDay(500) } })).status).toBe(400)
    expect((await call('/api/exceptions', 'operator', { method: 'POST', json: { project_id: crypto.randomUUID(), kind: 'rule', target: { rule_id: 'x' }, reason: 'inconnu', expires_on: isoDay(5) } })).status).toBe(404)
    expect((await call('/api/exceptions', 'viewer', { method: 'POST', json: { project_id: projectId, kind: 'rule', target: { rule_id: 'x' }, reason: 'lecteur', expires_on: isoDay(5) } })).status).toBe(403)
    const created = await call('/api/exceptions', 'operator', { method: 'POST', json: { project_id: projectId, kind: 'module', target: { module_id: 'trivy' }, reason: 'module en panne', expires_on: isoDay(3) } })
    expect(created.status).toBe(201)
    const list = await call(`/api/exceptions?project_id=${projectId}`, 'viewer')
    expect((list.data.items as unknown[]).length).toBe(1)
    expect((await call('/api/exceptions', 'viewer')).status).toBe(400)
    const revoked = await call(`/api/exceptions/${created.data.id as string}`, 'operator', { method: 'DELETE' })
    expect(revoked.data).toMatchObject({ active: false, revoked_by: 'operator' })
    expect((await call(`/api/exceptions?project_id=${projectId}&all=true`, 'viewer')).data.items).toHaveLength(1)
    expect((await call(`/api/exceptions/${crypto.randomUUID()}`, 'operator', { method: 'DELETE' })).status).toBe(404)
    expect((await call('/api/exceptions/x', 'operator', { method: 'DELETE' })).status).toBe(404)
  })

  it('gravités (G5) : lecture, modification par un administrateur, retour au défaut, audit', async () => {
    const list = await call('/api/severity-maps', 'viewer')
    expect(list.data.items).toEqual([expect.objectContaining({ module_id: 'trivy', native: 'level:error', severity: 'critical', origin: 'critical', builtin: true })])
    expect((await call('/api/severity-maps', 'operator', { method: 'PATCH', json: { module_id: 'trivy', native: 'level:error', severity: 'high' } })).status).toBe(403)
    const upd = await call('/api/severity-maps', 'admin', { method: 'PATCH', json: { module_id: 'trivy', native: 'level:error', severity: 'high' } })
    expect(upd.data).toEqual({ module_id: 'trivy', native: 'level:error', severity: 'high', builtin: false })
    const reset = await call('/api/severity-maps', 'admin', { method: 'PATCH', json: { module_id: 'trivy', native: 'level:error', severity: null } })
    expect(reset.data).toMatchObject({ severity: 'critical', builtin: true })
    expect((await call('/api/severity-maps', 'admin', { method: 'PATCH', json: { module_id: 'trivy', native: 'absent', severity: 'low' } })).status).toBe(404)
    const audit = await db.pool.query(`SELECT action, details FROM audit_log WHERE action LIKE 'severity-map.%' ORDER BY id`)
    expect(audit.rows.map(r => r.action)).toEqual(['severity-map.update', 'severity-map.reset'])
    expect(audit.rows[1].details).toMatchObject({ from: 'high', to: 'critical' })
  })
})
