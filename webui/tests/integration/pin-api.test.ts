// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// API de vigilance (0.6, chantier B) contre un vrai PostgreSQL 16 : rôles
// (lecteur, administrateur), versions figées (G6) avec motif, audit et
// pins.json, essais (F13) démarrés, abandonnés et adoptés par une mise à jour
// normale, relevé F19 et canaris G14 demandés au helper, vue d'un module,
// bandeau (« module X vulnérable, mise à jour disponible »).

import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import type { Role } from '#shared/schemas'
import vigilanceGet from '../../server/api/vigilance/index.get'
import selfVulnsGet from '../../server/api/vigilance/self-vulns.get'
import selfSbomPost from '../../server/api/vigilance/self-sbom.post'
import canariesPost from '../../server/api/vigilance/canaries.post'
import moduleVigilanceGet from '../../server/api/catalog/modules/[id]/vigilance.get'
import trialsPost from '../../server/api/catalog/modules/[id]/trials/index.post'
import trialAbandon from '../../server/api/catalog/modules/[id]/trials/[trial]/abandon.post'
import trialAdopt from '../../server/api/catalog/modules/[id]/trials/[trial]/adopt.post'
import pinsGet from '../../server/api/projects/[id]/pins/index.get'
import pinPut from '../../server/api/projects/[id]/pins/[module].put'
import pinDelete from '../../server/api/projects/[id]/pins/[module].delete'

const D_OLD = `sha256:${'a'.repeat(64)}`
const D_NEW = `sha256:${'b'.repeat(64)}`

describe.skipIf(!DATABASE_URL)('API de vigilance (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let project: string
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }

  async function call(path: string, role: Role, init: { method?: string, json?: unknown } = {}) {
    const res = await fetch(`${base}${path}`, {
      method: init.method ?? 'GET',
      headers: { 'x-test-role': role, ...(init.json === undefined ? {} : { 'content-type': 'application/json' }) },
      body: init.json === undefined ? undefined : JSON.stringify(init.json),
    })
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- réponses JSON lues librement par les assertions
    return { status: res.status, data: await res.json().catch(() => ({})) as Record<string, any> }
  }
  const requests = async () => (await readdir(join(root, 'requests', 'incoming'))).length

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-vig-api-'))
    for (const d of ['requests/incoming', 'requests/tmp', 'console', 'vigilance/self']) await mkdir(join(root, d), { recursive: true })
    const entry = (version: string, digest: string) => ({
      id: 'gitleaks', name: 'gitleaks', type: 'scanner', version, categories: ['secrets'], license: { spdx: 'MIT', restrictions: 'none' },
      image: `ghcr.io/exemple/gitleaks@${digest}`, requires: { modules: [], feeds: [] }, conflicts: [],
      resources: { min_ram_mb: 64, min_cpu: 1, disk_mb: 10 }, options: { type: 'object', properties: {} },
      outputs: { sarif: { path: '/out/result.sarif', version: '2.1.0' } },
      scan: { inputs: ['repo'], command: ['gitleaks'], timeout_s: 300, network: 'none' },
    })
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify({ schema: 1, version: 1, generated_at: '2026-11-24T00:00:00Z', packs: [],
      modules: [entry('8.30.0', D_OLD), entry('8.30.1', D_NEW)] }))
    await writeFile(join(root, 'modules-state.json'), JSON.stringify({ version: 1, updated_at: '2026-11-24T08:00:00Z', operations: [],
      modules: [{ id: 'gitleaks', version: '8.30.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-24T08:00:00Z', options: {}, testbed: null, route: null, last_error: null }] }))
    await writeFile(join(root, 'vigilance', 'state.json'), JSON.stringify({ version: 1, updated_at: '2026-11-24T08:00:00Z',
      retained: [{ module: 'gitleaks', version: '8.30.1', image_digest: D_NEW, kind: 'trial' }],
      self_sbom: { version: 1, at: '2026-11-24T05:00:00Z', gaps: ['syft-missing'], subjects: [{ subject: 'console', version: '0.6.0', components: 3, tools: [] }] } }))
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'), NUXT_MODULES_STATE_FILE: join(root, 'modules-state.json'),
      NUXT_REQUESTS_DIR: join(root, 'requests'), NUXT_STATE_FILE: join(root, 'state.json'), NUXT_VIGILANCE_STATE_FILE: join(root, 'vigilance', 'state.json'),
      NUXT_VIGILANCE_SELF_DIR: join(root, 'vigilance', 'self'), NUXT_PINS_FILE: join(root, 'pins', 'pins.json'),
    }))
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    project = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('vig', 'Vigilance', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)).rows[0]!.id
    await db.pool.query(`INSERT INTO self_vulns (subject, vuln_id, purl, severity, fixed_version, update_available)
      VALUES ('module:gitleaks', 'CVE-2026-0001', 'pkg:golang/x@1', 'critical', '1.1', true)`)
    await db.pool.query(`INSERT INTO canary_runs (module_id, module_version, ok, details, run_at) VALUES ('gitleaks', '8.30.0', false, '{"expect": []}', now())`)

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/vigilance', vigilanceGet)
    router.get('/api/vigilance/self-vulns', selfVulnsGet)
    router.post('/api/vigilance/self-sbom', selfSbomPost)
    router.post('/api/vigilance/canaries', canariesPost)
    router.get('/api/catalog/modules/:id/vigilance', moduleVigilanceGet)
    router.post('/api/catalog/modules/:id/trials', trialsPost)
    router.post('/api/catalog/modules/:id/trials/:trial/abandon', trialAbandon)
    router.post('/api/catalog/modules/:id/trials/:trial/adopt', trialAdopt)
    router.get('/api/projects/:id/pins', pinsGet)
    router.put('/api/projects/:id/pins/:module', pinPut)
    router.delete('/api/projects/:id/pins/:module', pinDelete)
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

  it('selfvuln-api : bandeau « vulnérable, mise à jour disponible », canari en échec, détail', async () => {
    const r = await call('/api/vigilance', 'viewer')
    expect(r.status).toBe(200)
    expect(r.data.alerts).toEqual([{ subject: 'module:gitleaks', update_available: '8.30.1', critical: 1, high: 0, total: 1 }])
    expect(r.data.canaries.failing).toEqual(['gitleaks'])
    expect(r.data.self_sbom).toMatchObject({ gaps: ['syft-missing'], subjects: [{ subject: 'console', components: 3 }] })
    expect(r.data.retained).toEqual([expect.objectContaining({ version: '8.30.1', kind: 'trial' })])
    const v = await call('/api/vigilance/self-vulns?subject=module:gitleaks', 'viewer')
    expect(v.data.vulns).toEqual([expect.objectContaining({ vuln_id: 'CVE-2026-0001', fixed_version: '1.1' })])
    expect((await call('/api/vigilance/self-vulns?subject=../etc', 'viewer')).status).toBe(400)
    expect((await call('/api/vigilance', 'admin')).status).toBe(200)
  })

  it('canary-api : relevé et canaris demandés au helper par un administrateur seulement', async () => {
    expect((await call('/api/vigilance/self-sbom', 'operator', { method: 'POST', json: {} })).status).toBe(403)
    expect((await call('/api/vigilance/canaries', 'operator', { method: 'POST', json: {} })).status).toBe(403)
    expect((await call('/api/vigilance/canaries', 'admin', { method: 'POST', json: { ids: ['../x'] } })).status).toBe(400)
    const before = await requests()
    expect((await call('/api/vigilance/self-sbom', 'admin', { method: 'POST', json: {} })).status).toBe(202)
    const c = await call('/api/vigilance/canaries', 'admin', { method: 'POST', json: { ids: ['gitleaks'] } })
    expect(c.status).toBe(202)
    expect(await requests()).toBe(before + 2)
    const req = (await db.pool.query('SELECT type, params FROM helper_requests WHERE id = $1', [c.data.request_id])).rows[0]
    expect(req).toEqual({ type: 'run-canaries', params: { ids: ['gitleaks'] } })
  })

  it('pin-api : figer (admin, motif), avertissements, pins.json, libérer', async () => {
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'operator', { method: 'PUT', json: { reason: 'audit' } })).status).toBe(403)
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'admin', { method: 'PUT', json: { reason: 'x' } })).status).toBe(400)
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'admin', { method: 'PUT', json: { reason: 'audit', image: D_NEW } })).status).toBe(400)
    const miss = await call(`/api/projects/${project}/pins/trivy`, 'admin', { method: 'PUT', json: { reason: 'audit' } })
    expect([miss.status, miss.data.data?.reason ?? miss.data.reason]).toEqual([409, 'E_PIN_MODULE'])
    const ok = await call(`/api/projects/${project}/pins/gitleaks`, 'admin', { method: 'PUT', json: { reason: 'audit de la release' } })
    expect(ok.status).toBe(200)
    expect(ok.data.pin).toMatchObject({ version: '8.30.0', image_digest: D_OLD })
    expect(JSON.parse(await readFile(join(root, 'pins', 'pins.json'), 'utf8')).pins).toEqual([{ module: 'gitleaks', version: '8.30.0', image_digest: D_OLD }])
    const list = await call(`/api/projects/${project}/pins`, 'viewer')
    expect(list.data.pins).toEqual([expect.objectContaining({ module_id: 'gitleaks', installed_version: '8.30.0', warnings: ['vulnerable'] })])
    expect(list.data.pinnable).toEqual([])
    const mv = await call('/api/catalog/modules/gitleaks/vigilance', 'viewer')
    expect(mv.data).toMatchObject({ trial_candidates: ['8.30.1'], pins: [{ slug: 'vig', version: '8.30.0', reason: 'audit de la release' }] })
    expect(mv.data.canaries).toHaveLength(1)
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'operator', { method: 'DELETE' })).status).toBe(403)
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'admin', { method: 'DELETE' })).status).toBe(200)
    expect((await call(`/api/projects/${project}/pins/gitleaks`, 'admin', { method: 'DELETE' })).status).toBe(404)
    expect(JSON.parse(await readFile(join(root, 'pins', 'pins.json'), 'utf8')).pins).toEqual([])
    expect((await call('/api/projects/00000000-0000-4000-8000-000000000000/pins', 'viewer')).status).toBe(404)
  })

  it('trial-api : démarrer, refus, abandon, adoption par update-module', async () => {
    expect((await call('/api/catalog/modules/gitleaks/trials', 'operator', { method: 'POST', json: {} })).status).toBe(403)
    expect((await call('/api/catalog/modules/gitleaks/trials', 'admin', { method: 'POST', json: { version: '8.30.1;rm' } })).status).toBe(400)
    const older = await call('/api/catalog/modules/gitleaks/trials', 'admin', { method: 'POST', json: { version: '8.29.0' } })
    expect([older.status, older.data.data?.reason]).toEqual([409, 'E_TRIAL_VERSION'])
    expect((await call('/api/catalog/modules/trivy/trials', 'admin', { method: 'POST', json: {} })).status).toBe(404)
    const s = await call('/api/catalog/modules/gitleaks/trials', 'admin', { method: 'POST', json: { sample_size: 2 } })
    expect(s.status).toBe(202)
    expect(s.data.version).toBe('8.30.1')
    const again = await call('/api/catalog/modules/gitleaks/trials', 'admin', { method: 'POST', json: {} })
    expect([again.status, again.data.data?.reason]).toEqual([409, 'E_TRIAL_RUNNING'])
    // Un essai en cours ne s'adopte pas.
    const early = await call(`/api/catalog/modules/gitleaks/trials/${s.data.trial_id}/adopt`, 'admin', { method: 'POST', json: {} })
    expect([early.status, early.data.data?.reason]).toEqual([409, 'E_TRIAL_STATE'])
    expect((await call('/api/catalog/modules/gitleaks/trials/pas-un-uuid/abandon', 'admin', { method: 'POST', json: {} })).status).toBe(404)
    const ab = await call(`/api/catalog/modules/gitleaks/trials/${s.data.trial_id}/abandon`, 'admin', { method: 'POST', json: {} })
    expect(ab.status).toBe(202)
    const twice = await call(`/api/catalog/modules/gitleaks/trials/${s.data.trial_id}/abandon`, 'admin', { method: 'POST', json: {} })
    expect([twice.status, twice.data.data?.reason]).toEqual([409, 'E_TRIAL_STATE'])

    const t = await call('/api/catalog/modules/gitleaks/trials', 'admin', { method: 'POST', json: {} })
    await db.pool.query(`UPDATE module_trials SET status = 'done', summary = '{"new": 0, "gone": 0, "unchanged": 0, "scans": 0, "failed": 0, "per_scan": []}' WHERE id = $1`, [t.data.trial_id])
    const ad = await call(`/api/catalog/modules/gitleaks/trials/${t.data.trial_id}/adopt`, 'admin', { method: 'POST', json: {} })
    expect(ad.status).toBe(202)
    const req = (await db.pool.query('SELECT type, params FROM helper_requests WHERE id = $1', [ad.data.request_id])).rows[0]
    expect(req).toEqual({ type: 'update-module', params: { id: 'gitleaks', version: '8.30.1' } })
    const mv = await call('/api/catalog/modules/gitleaks/vigilance', 'viewer')
    expect(mv.data.trials.map((x: { status: string }) => x.status)).toEqual(['adopted', 'abandoned'])
    const audit = (await db.pool.query(`SELECT action FROM audit_log WHERE action LIKE 'module.trial-%' ORDER BY id`)).rows.map(r => r.action)
    expect(audit).toEqual(['module.trial-start', 'module.trial-abandon', 'module.trial-start'])
  })
})
