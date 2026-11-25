// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : VEX (H7, contrat 38) contre un vrai PostgreSQL 16.
// Génération depuis les exceptions approuvées avec vex_status (purl tiré du
// SBOM), forme canonique stable, export OpenVEX et CycloneDX, filtre par
// analyse, révocation, exception échue, import en DEMANDES d'exception
// (jamais en approbation), H4, doublons, API.

import { randomBytes } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { decideException, ExceptionError, isoDay, requestException, revokeException, type ExceptionRequestInput } from '../../server/findings/exceptions'
import { activeStatements, buildVex, exportVex, importVex, VexError } from '../../server/vex/vex'
import { purlOf, syncExceptionVex } from '../../server/vex/sync'
import { parseVexDocument, VexFormatError } from '../../server/vex/format'
import exportRoute from '../../server/api/vex/projects/[id]/export.get'
import importRoute from '../../server/api/vex/projects/[id]/import.post'
import statementsRoute from '../../server/api/vex/projects/[id]/statements.get'

describe.skipIf(!DATABASE_URL)('VEX (H7, PostgreSQL réel)', () => {
  let db: TestDatabase
  let server: Server
  let base: string
  let projectId: string
  let scanId: string
  let otherScanId: string
  let findingId: string
  const users = {} as Record<'ops' | 'chef' | 'adjoint' | 'lecteur', { id: number, role: 'viewer' | 'operator' | 'admin' }>

  const req = (over: Partial<ExceptionRequestInput> = {}): ExceptionRequestInput => ({
    project_id: projectId, kind: 'vuln', target: { vuln_id: 'CVE-2026-2001' },
    reason: '[vulnerable_code_not_in_execute_path] La fonction vulnérable n\'est jamais appelée par le projet.',
    expires_on: isoDay(60), requested_via: 'console', requester_label: 'ops', requester_is_human: true,
    requester_user_id: users.ops.id, commit_authors: [], vex_status: 'not_affected', ...over,
  })
  const approve = (id: string, who: 'chef' | 'adjoint' = 'chef') => decideException(db.pool, id, { decision: 'approved', reason: 'vu et accepté', deciderUserId: users[who].id })

  async function call(path: string, who: keyof typeof users, init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-user': who, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    return { status: res.status, headers: res.headers, text: await res.text() }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url }))
    const mk = async (who: keyof typeof users, role: 'viewer' | 'operator' | 'admin') => {
      users[who] = { id: Number((await createUser(db.pool, { username: who, role, password: `${who}-long-password` })).id), role }
    }
    await mk('ops', 'operator')
    await mk('chef', 'admin')
    await mk('adjoint', 'admin')
    await mk('lecteur', 'viewer')
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('vex', 'VEX', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    const mkScan = async (n: number) => (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, finished_at, verdict)
       VALUES ($1, $2, 'manual', 50, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'),
               'done', '2026-11-20T10:00:00Z', 'failed') RETURNING id`, [projectId, n])).rows[0]!.id
    scanId = await mkScan(1)
    otherScanId = await mkScan(2)
    await db.pool.query(
      `INSERT INTO sbom_components (scan_id, project_id, purl, ecosystem, name, version)
       VALUES ($1, $2, 'pkg:npm/example-parser@1.0.0', 'npm', 'example-parser', '1.0.0')`, [scanId, projectId])
    findingId = (await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids, package)
       VALUES ($1, $2, 'osv-scanner', 'CVE-2026-2001', 'sca', 'high', 't', 'package-lock.json', '{CVE-2026-2001,GHSA-aaaa-bbbb-cccc}',
               '{"ecosystem": "npm", "name": "example-parser", "version": "1.0.0"}') RETURNING id`,
      [projectId, randomBytes(32).toString('hex')])).rows[0]!.id
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [scanId, findingId])

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const who = getHeader(event, 'x-test-user') as keyof typeof users | undefined
      if (who) event.context.auth = { user: { id: users[who].id, username: who, displayName: null, role: users[who].role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/vex/projects/:id/export', exportRoute)
    router.get('/api/vex/projects/:id/statements', statementsRoute)
    router.post('/api/vex/projects/:id/import', importRoute)
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
  })

  it('une demande avec statut VEX ne donne rien tant qu\'elle n\'est pas approuvée', async () => {
    const r = await requestException(db.pool, req())
    expect(r.vex_status).toBe('not_affected')
    expect((await buildVex(db.pool, projectId)).statements).toEqual([])
    await db.pool.query('DELETE FROM exceptions WHERE id = $1', [r.id])
  })

  it('statut VEX refusé hors d\'une exception de vulnérabilité ou inconnu', async () => {
    await expect(requestException(db.pool, req({ kind: 'rule', target: { rule_id: 'R1' } }))).rejects.toThrow('E_VALIDATION')
    await expect(requestException(db.pool, req({ vex_status: 'peut-être' }))).rejects.toThrow('E_VALIDATION')
  })

  it('approbation : déclaration matérialisée, purl du SBOM, justification tirée du motif, forme canonique stable', async () => {
    const r = await requestException(db.pool, req())
    await approve(r.id)
    const rows = await db.pool.query('SELECT vuln_id, product, status, justification, source FROM vex_statements WHERE exception_id = $1 AND revoked_at IS NULL', [r.id])
    expect(rows.rows).toEqual([{ vuln_id: 'CVE-2026-2001', product: 'pkg:npm/example-parser@1.0.0', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path', source: 'exception' }])
    const a = await buildVex(db.pool, projectId)
    const b = await buildVex(db.pool, projectId)
    expect(a.sha256).toBe(b.sha256)
    expect(a.canonical).toBe(b.canonical)
    expect(a.document).toMatchObject({ '@context': 'https://openvex.dev/ns/v0.2.0', 'author': 'Scanoria', 'version': 1 })
    const st = (a.document.statements as Record<string, unknown>[])[0]!
    expect(st).toMatchObject({ status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path', vulnerability: { name: 'CVE-2026-2001' } })
    expect(st.impact_statement).toBe('La fonction vulnérable n\'est jamais appelée par le projet.')
    // Une resynchronisation ne duplique rien.
    expect(await syncExceptionVex(db.pool, r.id)).toBe(1)
    expect((await db.pool.query('SELECT 1 FROM vex_statements WHERE exception_id = $1', [r.id])).rowCount).toBe(1)

    // Par analyse : seules les vulnérabilités vues par l'analyse ; horodatage de l'analyse.
    const scoped = await buildVex(db.pool, projectId, { scanId })
    expect(scoped.statements).toHaveLength(1)
    expect(scoped.document.timestamp).toBe('2026-11-20T10:00:00Z')
    expect((await buildVex(db.pool, projectId, { scanId: otherScanId })).statements).toEqual([])
    await expect(buildVex(db.pool, projectId, { scanId: crypto.randomUUID() })).rejects.toBeInstanceOf(VexError)
    await expect(buildVex(db.pool, crypto.randomUUID())).rejects.toThrow('E_NOT_FOUND')

    // Export OpenVEX et CycloneDX : mêmes déclarations, relues à l'identique.
    const ov = await exportVex(db.pool, projectId, { format: 'openvex' })
    expect(ov).toMatchObject({ contentType: 'application/json', filename: 'vex.openvex.json', count: 1 })
    expect(ov.body).toBe(a.canonical)
    const cdx = await exportVex(db.pool, projectId, { format: 'cyclonedx', scanId })
    expect(cdx).toMatchObject({ contentType: 'application/vnd.cyclonedx+json', filename: 'vex-scan.cdx.vex.json' })
    const back = parseVexDocument(cdx.body).statements
    expect(back).toMatchObject([{ vuln_id: 'CVE-2026-2001', product: 'pkg:npm/example-parser@1.0.0', status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' }])

    // Révocation : la déclaration est révoquée avec l'exception.
    await revokeException(db.pool, r.id, users.chef.id)
    expect((await db.pool.query('SELECT 1 FROM vex_statements WHERE exception_id = $1 AND revoked_at IS NOT NULL', [r.id])).rowCount).toBe(1)
    expect((await buildVex(db.pool, projectId)).statements).toEqual([])
  })

  it('exception sur un résultat : statut affected avec action, paquet du résultat ; exception échue ignorée', async () => {
    const r = await requestException(db.pool, req({ kind: 'finding', target: { finding_id: findingId }, vex_status: 'affected', reason: 'Correctif prévu, en attente de la version 1.0.1.' }))
    await approve(r.id, 'adjoint')
    const list = await activeStatements(db.pool, projectId)
    expect(list.map(s => s.vuln_id).sort()).toEqual(['CVE-2026-2001', 'GHSA-aaaa-bbbb-cccc'])
    expect(list[0]).toMatchObject({ status: 'affected', action_statement: 'Correctif prévu, en attente de la version 1.0.1.', justification: null })
    // Échue (date de fin passée) : plus aucune déclaration, sans action de personne.
    await db.pool.query(`UPDATE exceptions SET expires_on = current_date - 1 WHERE id = $1`, [r.id])
    expect(await activeStatements(db.pool, projectId)).toEqual([])
    expect(await syncExceptionVex(db.pool, r.id)).toBe(0)
  })

  it('exception sur un résultat : version exacte seulement ; statut VEX refusé sans vulnérabilité ; aperçu aligné sur la validation', async () => {
    await db.pool.query(
      `INSERT INTO sbom_components (scan_id, project_id, purl, ecosystem, name, version)
       VALUES ($1, $2, 'pkg:npm/example-parser@2.0.0', 'npm', 'example-parser', '2.0.0')`, [scanId, projectId])
    const r = await requestException(db.pool, req({ kind: 'finding', target: { finding_id: findingId }, vex_status: 'not_affected' }))
    await approve(r.id)
    const products = (await db.pool.query<{ product: string }>('SELECT DISTINCT product FROM vex_statements WHERE exception_id = $1', [r.id])).rows.map(x => x.product)
    expect(products).toEqual(['pkg:npm/example-parser@1.0.0'])
    await revokeException(db.pool, r.id, users.chef.id)
    await db.pool.query(`DELETE FROM sbom_components WHERE purl = 'pkg:npm/example-parser@2.0.0'`)

    const plain = (await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path)
       VALUES ($1, $2, 'semgrep', 'R1', 'sast', 'high', 't', 'a.js') RETURNING id`, [projectId, randomBytes(32).toString('hex')])).rows[0]!.id
    await expect(requestException(db.pool, req({ kind: 'finding', target: { finding_id: plain }, vex_status: 'not_affected' }))).rejects.toThrow('E_VALIDATION')

    const doc = JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'urn:example:vex:1', 'author': 'exemple.test', 'timestamp': '2026-11-20T10:00:00Z', 'version': 1,
      'statements': [{ vulnerability: { name: 'RUSTSEC_2020_0001' }, products: [{ '@id': 'pkg:cargo/example@1.0.0' }], status: 'fixed' }],
    })
    const res = await importVex(db.pool, projectId, doc, { dryRun: true, actor: { userId: users.ops.id, username: 'ops' } })
    expect(res.effects).toMatchObject([{ action: 'refused', reason: 'validation' }])
  })

  it('exception approuvée avant la 0.8 (sans déclaration matérialisée) : déclaration dérivée à la lecture', async () => {
    const id = (await db.pool.query<{ id: string }>(
      `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, status, decided_at, decided_by, vex_status)
       VALUES ($1, 'vuln', '{"vuln_id": "CVE-2026-2009", "package": "other-lib"}', 'Composant absent de l''image livrée.', current_date + 10,
               'approved', now(), $2, 'fixed') RETURNING id`, [projectId, users.chef.id])).rows[0]!.id
    const list = await activeStatements(db.pool, projectId)
    expect(list).toMatchObject([{ vuln_id: 'CVE-2026-2009', product: 'pkg:generic/other-lib', status: 'fixed', impact_statement: 'Composant absent de l\'image livrée.' }])
    await db.pool.query('DELETE FROM exceptions WHERE id = $1', [id])
  })

  it('purl reconstruit depuis un paquet', () => {
    expect(purlOf({ ecosystem: 'npm', name: '@scope/lib', version: '2.0.0' })).toBe('pkg:npm/%40scope/lib@2.0.0')
    expect(purlOf({ ecosystem: 'PyPI', name: 'requests' })).toBe('pkg:pypi/requests')
    expect(purlOf({ ecosystem: 'Inconnu !', name: 'x' })).toBe('pkg:generic/x')
    expect(purlOf({ name: null })).toBeNull()
  })

  const openvex = (statements: unknown[]) => JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', '@id': 'urn:x', 'author': 'Fournisseur', 'timestamp': '2026-11-01T00:00:00Z', 'version': 1, statements })
  const stmt = (vuln: string, status: string, extra: Record<string, unknown> = {}) => ({
    vulnerability: { name: vuln }, products: [{ '@id': 'pkg:npm/example-parser@1.0.0' }], status, ...extra,
  })

  it('import : aperçu sans écriture, puis demandes d\'exception jamais approuvées, statuts informatifs gardés, H4 refusé', async () => {
    const doc = openvex([
      stmt('CVE-2026-3001', 'not_affected', { justification: 'component_not_present' }),
      stmt('CVE-2026-3002', 'fixed', { impact_statement: 'Corrigé dans notre construction.' }),
      stmt('CVE-2026-3003', 'affected', { action_statement: 'Mise à jour prévue.' }),
      stmt('MAL-2026-0001', 'not_affected', { justification: 'component_not_present' }),
    ])
    const actor = { userId: users.ops.id, username: 'ops' }
    const before = Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM exceptions')).rows[0]!.n)
    const preview = await importVex(db.pool, projectId, doc, { dryRun: true, actor })
    expect(preview.counts).toEqual({ request: 2, store: 1, duplicate: 0, refused: 1 })
    expect(Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM exceptions')).rows[0]!.n)).toBe(before)

    const done = await importVex(db.pool, projectId, doc, { dryRun: false, actor })
    expect(done.counts).toEqual({ request: 2, store: 1, duplicate: 0, refused: 1 })
    const requests = await db.pool.query<{ status: string, requested_via: string, vex_status: string, reason: string, target: Record<string, unknown> }>(
      `SELECT status, requested_via, vex_status, reason, target FROM exceptions WHERE requested_via = 'tool-import' ORDER BY target->>'vuln_id'`)
    expect(requests.rows.map(r => [r.status, r.vex_status, r.target.vuln_id, r.target.package])).toEqual([
      ['requested', 'not_affected', 'CVE-2026-3001', 'example-parser'],
      ['requested', 'fixed', 'CVE-2026-3002', 'example-parser'],
    ])
    expect(requests.rows[0]!.reason.startsWith('[component_not_present] ')).toBe(true)
    // Rien n'est encore déclaré : une demande n'est pas une approbation.
    expect((await activeStatements(db.pool, projectId)).map(s => s.vuln_id)).toEqual(['CVE-2026-3003'])
    // Celui qui importe ne peut pas approuver sa propre demande.
    const id = (await db.pool.query<{ id: string }>(`SELECT id FROM exceptions WHERE target->>'vuln_id' = 'CVE-2026-3001'`)).rows[0]!.id
    await expect(decideException(db.pool, id, { decision: 'approved', reason: 'moi-même', deciderUserId: users.ops.id })).rejects.toBeInstanceOf(ExceptionError)
    // Approuvée par un administrateur : la déclaration apparaît, avec la justification importée.
    await approve(id)
    expect((await activeStatements(db.pool, projectId)).find(s => s.vuln_id === 'CVE-2026-3001')).toMatchObject({ justification: 'component_not_present', status: 'not_affected' })
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'vex.import'`)).rowCount).toBe(1)

    // Second import : doublons reconnus.
    const again = await importVex(db.pool, projectId, doc, { dryRun: false, actor })
    expect(again.counts).toEqual({ request: 0, store: 0, duplicate: 3, refused: 1 })
    await expect(importVex(db.pool, projectId, doc, { dryRun: true, actor, expiresOn: isoDay(400) })).rejects.toThrow('E_VALIDATION')
  })

  it('import : documents hostiles refusés en entier', async () => {
    const actor = { userId: users.ops.id, username: 'ops' }
    const bad = async (text: string, code: string) => {
      const err = await importVex(db.pool, projectId, text, { dryRun: true, actor }).catch(e => e)
      expect(err).toBeInstanceOf(VexFormatError)
      expect(err.code).toBe(code)
    }
    await bad('{', 'E_VEX_JSON')
    await bad('[]', 'E_VEX_FORMAT')
    await bad(openvex([stmt('CVE-2026-1', 'peut-etre')]), 'E_VEX_STATUS')
    await bad(openvex([stmt('$(id)', 'fixed')]), 'E_VEX_VULN_ID')
    await bad(openvex([{ ...stmt('CVE-2026-3009', 'fixed'), products: [{ '@id': 'pkg:npm/../../etc/passwd x' }] }]), 'E_VEX_PRODUCT')
    await bad(openvex([stmt('CVE-2026-3009', 'not_affected')]), 'E_VEX_JUSTIFICATION')
    let deep: unknown = 'x'
    for (let i = 0; i < 40; i++) deep = { a: deep }
    await bad(JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', 'statements': [stmt('CVE-2026-3009', 'fixed', { x: deep })] }), 'E_VEX_TOO_DEEP')
  })

  it('API : export (en-têtes, empreinte), déclarations, import (aperçu, rôles, erreurs)', async () => {
    const e = await call(`/api/vex/projects/${projectId}/export?format=cyclonedx`, 'lecteur')
    expect(e.status).toBe(200)
    expect(e.headers.get('content-type')).toContain('application/vnd.cyclonedx+json')
    expect(e.headers.get('content-disposition')).toContain('vex.cdx.vex.json')
    expect(e.headers.get('x-scanoria-sha256')).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.parse(e.text).bomFormat).toBe('CycloneDX')
    expect((await call(`/api/vex/projects/${projectId}/export?format=spdx`, 'lecteur')).status).toBe(400)
    expect((await call(`/api/vex/projects/${crypto.randomUUID()}/export`, 'lecteur')).status).toBe(404)
    const s = await call(`/api/vex/projects/${projectId}/statements`, 'lecteur')
    expect(JSON.parse(s.text).statements.length).toBeGreaterThan(0)

    const doc = openvex([stmt('CVE-2026-3100', 'fixed', { impact_statement: 'Corrigé.' })])
    expect((await call(`/api/vex/projects/${projectId}/import`, 'lecteur', { method: 'POST', json: { document: doc } })).status).toBe(403)
    const p = await call(`/api/vex/projects/${projectId}/import`, 'ops', { method: 'POST', json: { document: doc } })
    expect(p.status).toBe(200)
    expect(JSON.parse(p.text)).toMatchObject({ dry_run: true, counts: { request: 1 } })
    const bad = await call(`/api/vex/projects/${projectId}/import`, 'ops', { method: 'POST', json: { document: '{"bomFormat":"CycloneDX","specVersion":"1.6"}', dry_run: false } })
    expect(bad.status).toBe(400)
    expect(JSON.parse(bad.text).data).toMatchObject({ code: 'E_VALIDATION', reason: 'E_VEX_FORMAT' })
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'vex.import' AND outcome = 'failure'`)).rowCount).toBe(1)
  })
})
