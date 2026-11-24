// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F16 (0.5, chantier C) contre un vrai PostgreSQL 16 : clé de recoupement
// posée à l'ingestion (contrat 18) sans toucher à l'empreinte G19, groupe
// « confirmé par N outils » dans la liste et le détail, mode groupé, tri d'un
// groupe (une ligne d'audit par résultat, H4 refusé), quality gate qui compte
// le groupe une fois, reprise idempotente des résultats existants.

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { finalizeScanFindings, ingestModuleOutputs } from '../../server/findings/ingest'
import { getFinding, listFindings } from '../../server/findings/triage'
import { evaluateGate } from '../../server/gates/evaluate'
import { BACKFILL_SETTING, backfillCorrelationKeys, correlationKey, groupMemberIds, groupOf } from '../../server/findings/correlation'
import { fingerprintOf } from '../../server/findings/normalize'
import type { Role } from '#shared/schemas'
import groupGet from '../../server/api/findings/[id]/group.get'
import groupStatus from '../../server/api/findings/[id]/group-status.post'
import listApi from '../../server/api/findings/index.get'

function sarif(tool: string, results: unknown[]) {
  return { version: '2.1.0', runs: [{ tool: { driver: { name: tool, rules: [] } }, results }] }
}
const dep = (rule: string, aliases: string[], purl: string, level = 'error') => ({
  ruleId: rule, level, message: { text: `vulnérabilité ${rule}` },
  locations: [{ physicalLocation: { artifactLocation: { uri: 'package-lock.json' } } }],
  properties: { purl, aliases },
})

describe.skipIf(!DATABASE_URL)('recoupement entre outils (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let scanId: string
  let server: Server
  let base: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }

  async function ingest(moduleId: string, doc: unknown) {
    const resultDir = join(root, 'results', scanId)
    await mkdir(join(resultDir, moduleId), { recursive: true })
    await writeFile(join(resultDir, moduleId, 'r.sarif'), JSON.stringify(doc))
    return ingestModuleOutputs(db.pool, { scanId, moduleId, resultDir, outputs: { sarif: `${moduleId}/r.sarif` } })
  }
  async function call(path: string, role: Role, init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-role': role, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    return { status: res.status, data: await res.json().catch(() => ({})) as Record<string, unknown> }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-correlation-'))
    const index = { schema: 1, version: 1, modules: [
      { id: 'osv-scanner', version: '1.0.0', categories: ['sca'] },
      { id: 'trivy', version: '1.0.0', categories: ['sca'] },
      { id: 'semgrep', version: '1.0.0', categories: ['sast'] },
      { id: 'bandit', version: '1.0.0', categories: ['sast'] },
    ] }
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify(index))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('corr', 'Recoupement', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`,
    )).rows[0]!.id
    scanId = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, job_id, started_at)
       VALUES ($1, 1, 'manual', 50, 'main', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', gen_random_uuid(), now())
       RETURNING id`, [projectId],
    )).rows[0]!.id
    for (const m of ['osv-scanner', 'trivy', 'semgrep', 'bandit']) {
      await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '1.0.0', 'ok')`, [scanId, m])
    }
    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/findings', listApi)
    router.get('/api/findings/:id/group', groupGet)
    router.post('/api/findings/:id/group-status', groupStatus)
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

  it('ingestion : même CVE et même paquet vus par deux outils → même clé, empreintes G19 distinctes', async () => {
    await ingest('osv-scanner', sarif('osv-scanner', [dep('GHSA-xvch-5gv4-984h', ['CVE-2021-44906'], 'pkg:npm/minimist@1.2.5', 'warning')]))
    await ingest('trivy', sarif('trivy', [dep('CVE-2021-44906', [], 'pkg:npm/minimist@1.2.5', 'error'), dep('CVE-2026-0001', [], 'pkg:npm/left-pad@1.0.0', 'note')]))
    await ingest('semgrep', sarif('semgrep', [{ ruleId: 'python.sqli', level: 'error', message: { text: 'injection SQL' }, properties: { tags: ['CWE-89: SQL Injection'] },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'app/db.py' }, region: { startLine: 4, snippet: { text: 'cur.execute("SELECT " + q)' } } } }] }]))
    await ingest('bandit', sarif('bandit', [{ ruleId: 'B608', level: 'warning', message: { text: 'Possible SQL injection' }, properties: { tags: ['CWE-89'] },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'app/db.py' }, region: { startLine: 4, snippet: { text: '  cur.execute("SELECT "  + q)' } } } }] }]))
    await finalizeScanFindings(db.pool, scanId, { complete: true })

    const rows = (await db.pool.query<{ id: string, tool: string, rule_id: string, fingerprint: string, correlation_key: string | null, category: string }>(
      'SELECT id, tool, rule_id, fingerprint, correlation_key, category FROM findings ORDER BY tool, rule_id',
    )).rows
    const minimist = rows.filter(r => r.rule_id.includes('44906') || r.rule_id.startsWith('GHSA'))
    expect(minimist).toHaveLength(2)
    expect(minimist[0]!.correlation_key).toMatch(/^[0-9a-f]{64}$/)
    expect(minimist[0]!.correlation_key).toBe(minimist[1]!.correlation_key)
    expect(minimist[0]!.fingerprint).not.toBe(minimist[1]!.fingerprint)
    // Empreinte G19 de la 0.3, inchangée par le recoupement.
    const trivyRow = rows.find(r => r.tool === 'trivy' && r.rule_id === 'CVE-2021-44906')!
    expect(trivyRow.fingerprint).toBe(fingerprintOf({ tool: 'trivy', ruleId: 'CVE-2021-44906', path: 'package-lock.json', context: '', pkg: { ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: [] }, vulnId: 'CVE-2021-44906', partial: null }))
    const sast = rows.filter(r => r.category === 'sast')
    expect(sast).toHaveLength(2)
    expect(sast[0]!.correlation_key).not.toBeNull()
    expect(sast[0]!.correlation_key).toBe(sast[1]!.correlation_key)
    expect(rows.find(r => r.rule_id === 'CVE-2026-0001')!.correlation_key).not.toBe(minimist[0]!.correlation_key)
  })

  it('liste : « confirmé par 2 outils », mode groupé à un résultat par problème', async () => {
    const flat = await listFindings(db.pool, { limit: 50, offset: 0 })
    expect(flat.total).toBe(5)
    const m = flat.items.find(i => i.rule_id === 'CVE-2021-44906')!
    expect(m.group).toMatchObject({ confirmations: 2, tools: ['osv-scanner', 'trivy'] })
    expect(m.group!.members).toHaveLength(2)
    expect(m.group!.size).toBe(2)
    expect(await groupMemberIds(db.pool, m.id)).toEqual(m.group!.members.map(x => x.id).sort())
    expect(await groupMemberIds(db.pool, crypto.randomUUID())).toBeNull()
    expect(flat.items.find(i => i.rule_id === 'CVE-2026-0001')!.group).toMatchObject({ confirmations: 1 })

    const grouped = await listFindings(db.pool, { limit: 50, offset: 0, grouped: true })
    expect(grouped.total).toBe(3)
    expect(grouped.items).toHaveLength(3)
    // Représentant : le plus grave du groupe.
    const rep = grouped.items.find(i => i.group?.tools.includes('osv-scanner'))!
    expect(rep.tool).toBe('trivy')
    const api = await call('/api/findings?grouped=true&limit=1', 'viewer')
    expect(api.status).toBe(200)
    expect(api.data.total).toBe(3)
    expect((api.data.items as unknown[]).length).toBe(1)

    const detail = await getFinding(db.pool, m.id)
    expect(detail!.group!.confirmations).toBe(2)
    const g = await call(`/api/findings/${m.id}/group`, 'viewer')
    expect((g.data.group as { confirmations: number }).confirmations).toBe(2)
    expect((await call(`/api/findings/${crypto.randomUUID()}/group`, 'viewer')).status).toBe(404)
    expect((await call('/api/findings/pas-un-uuid/group', 'viewer')).status).toBe(404)
    const lone = flat.items.find(i => i.category === 'quality' || i.rule_id === 'CVE-2026-0001')!
    expect(await groupOf(db.pool, lone.id)).toMatchObject({ confirmations: 1 })
  })

  it('quality gate : le groupe compte une seule fois', async () => {
    const v = await evaluateGate(db.pool, scanId)
    const total = Object.values(v.counts).reduce((a, b) => a + b, 0)
    expect(total).toBe(3)
  })

  it('tri d’un groupe : chaque résultat, une ligne d’audit par résultat ; rôle opérateur exigé', async () => {
    const m = (await listFindings(db.pool, { limit: 50, offset: 0 })).items.find(i => i.rule_id === 'CVE-2021-44906')!
    expect((await call(`/api/findings/${m.id}/group-status`, 'viewer', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(403)
    const r = await call(`/api/findings/${m.id}/group-status`, 'operator', { method: 'POST', json: { status: 'false-positive', reason: 'dépendance de test seulement' } })
    expect(r.status).toBe(200)
    expect((r.data.updated as string[]).sort()).toEqual(m.group!.members.map(x => x.id).sort())
    const st = await db.pool.query<{ status: string }>('SELECT status FROM findings WHERE correlation_key = $1', [m.correlation_key])
    expect(st.rows.map(x => x.status)).toEqual(['false-positive', 'false-positive'])
    const audit = await db.pool.query<{ n: string }>(`SELECT count(*) AS n FROM audit_log WHERE action = 'finding.status' AND outcome = 'success' AND details->>'group_of' = $1`, [m.id])
    expect(Number(audit.rows[0]!.n)).toBe(2)
    expect((await call(`/api/findings/${m.id}/group-status`, 'operator', { method: 'POST', json: { status: 'accepted', reason: 'x', until: '2000-01-01' } })).status).toBe(400)
    // Résultat sans groupe : seulement lui.
    const lone = (await listFindings(db.pool, { limit: 50, offset: 0 })).items.find(i => i.rule_id === 'CVE-2026-0001')!
    const one = await call(`/api/findings/${lone.id}/group-status`, 'operator', { method: 'POST', json: { status: 'confirmed' } })
    expect(one.data.updated).toEqual([lone.id])
  })

  it('H4 : un groupe qui contient un paquet malveillant ne peut pas être classé faux positif', async () => {
    const m = (await listFindings(db.pool, { limit: 50, offset: 0 })).items.find(i => i.rule_id === 'CVE-2021-44906')!
    await db.pool.query('UPDATE findings SET malicious = true, status = $2 WHERE id = $1', [m.id, 'new'])
    const r = await call(`/api/findings/${m.id}/group-status`, 'operator', { method: 'POST', json: { status: 'false-positive', reason: 'essai refusé' } })
    expect(r.status).toBe(409)
    expect((r.data.data as { code: string }).code).toBe('E_MALICIOUS')
    const st = await db.pool.query<{ status: string }>('SELECT status FROM findings WHERE id = $1', [m.id])
    expect(st.rows[0]!.status).toBe('new')
    await db.pool.query('UPDATE findings SET malicious = false WHERE id = $1', [m.id])
    expect((await call(`/api/findings/${crypto.randomUUID()}/group-status`, 'operator', { method: 'POST', json: { status: 'confirmed' } })).status).toBe(404)
  })

  it('reprise au démarrage : idempotente, par lots, puis plus rien à relire', async () => {
    const before = (await db.pool.query<{ id: string, correlation_key: string | null }>('SELECT id, correlation_key FROM findings ORDER BY id')).rows
    await db.pool.query('UPDATE findings SET correlation_key = NULL')
    await db.pool.query('DELETE FROM appliance_settings WHERE key = $1', [BACKFILL_SETTING])
    const first = await backfillCorrelationKeys(db.pool, { batch: 2 })
    expect(first.scanned).toBe(5)
    expect(first.updated).toBe(before.filter(r => r.correlation_key).length)
    const after = (await db.pool.query<{ id: string, correlation_key: string | null }>('SELECT id, correlation_key FROM findings ORDER BY id')).rows
    expect(after).toEqual(before)
    expect(await backfillCorrelationKeys(db.pool)).toEqual({ scanned: 0, updated: 0 })
    // Reprise interrompue : repart du dernier lot enregistré.
    await db.pool.query(`UPDATE appliance_settings SET value = jsonb_set(value, '{done}', 'false') WHERE key = $1`, [BACKFILL_SETTING])
    const resumed = await backfillCorrelationKeys(db.pool)
    expect(resumed.updated).toBe(0)
    // Une clé recalculée par le code est identique à celle posée à l'ingestion.
    const f = (await db.pool.query('SELECT category, cwe, vuln_ids, package, path, snippet, start_line, secret_type, correlation_key FROM findings')).rows
    for (const r of f) expect(correlationKey(r)).toBe(r.correlation_key)
  })
})
