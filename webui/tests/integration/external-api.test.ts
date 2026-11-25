// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J6 (0.6, contrat 26) contre un vrai PostgreSQL 16 : POST
// /api/projects/:id/results avec SARIF 2.1.0 et CycloneDX 1.5 / 1.6 valides,
// invalides, tronqués et trop gros ; droits (jeton du projet, autre projet,
// portée, rôles) ; gravités (G5, défaut medium) ; origine « external » et
// source ; quality gate ; SBOM visible (contrat 14) ; aucun cache V4 ;
// comparaison « nouveau » jamais croisée entre analyses externes et analyses
// de l'appliance ; filtre par origine ; client scanoria-scan upload.

import { execFile } from 'node:child_process'
import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { badTokenLimiter, tokenLimiter } from '../../server/middleware/api-token'
import { finalizeScanFindings } from '../../server/findings/ingest'
import { acquireExternalSlot, EXTERNAL_MAX_BYTES } from '../../server/external/ingest'
import { latestVerdict } from '../../server/gates/badge'
import { getProject } from '../../server/projects/service'

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))
const CLIENT = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/client/scanoria-scan', import.meta.url))
const run = promisify(execFile)

function apiRoutes(): { method: string, path: string, file: string }[] {
  const out: { method: string, path: string, file: string }[] = []
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
        continue
      }
      const m = /^(.+)\.(get|post|put|patch|delete)\.ts$/.exec(entry.name)
      if (!m) continue
      const segments = relative(API_DIR, dir).split(sep).filter(Boolean)
      if (m[1] !== 'index') segments.push(m[1]!)
      out.push({ method: m[2]!, path: `/api/${segments.map(s => s.replace(/^\[(.+)\]$/, ':$1')).join('/')}`.replace(/\/$/, ''), file: full })
    }
  }
  walk(API_DIR)
  return out.sort((a, b) => a.path.split(':').length - b.path.split(':').length)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>
interface Client { cookie: string, csrf: string }

const sarif = (results: unknown[], driver: Record<string, unknown> = { name: 'Acme SAST', version: '4.2.0' }, extra: Record<string, unknown> = {}) => ({
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
  version: '2.1.0',
  runs: [{ tool: { driver }, results }],
  ...extra,
})
const result = (ruleId: string, path: string, props: Record<string, unknown> = {}, level?: string) => ({
  ruleId,
  ...(level ? { level } : {}),
  message: { text: `problème ${ruleId}` },
  locations: [{ physicalLocation: { artifactLocation: { uri: path }, region: { startLine: 3 } } }],
  properties: props,
})
const cdx = (spec = '1.6', vulns: unknown[] = []) => ({
  bomFormat: 'CycloneDX',
  specVersion: spec,
  metadata: { tools: { components: [{ type: 'application', name: 'Acme SCA', version: '9.1' }] } },
  components: [
    { 'type': 'library', 'bom-ref': 'pkg:npm/minimist@1.2.5', 'name': 'minimist', 'version': '1.2.5', 'purl': 'pkg:npm/minimist@1.2.5', 'licenses': [{ license: { id: 'MIT' } }] },
    { 'type': 'library', 'bom-ref': 'pkg:npm/left-pad@1.3.0', 'name': 'left-pad', 'version': '1.3.0', 'purl': 'pkg:npm/left-pad@1.3.0' },
  ],
  vulnerabilities: vulns,
})

describe.skipIf(!DATABASE_URL)('résultats externes J6 (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let operator: Client
  let viewer: Client
  let gateId: string
  let profileId: string
  let projectA: string
  let projectB: string
  let token: string
  let ipCounter = 10
  const nextIp = () => `198.51.100.${ipCounter++}`

  async function call(path: string, init: RequestInit & { client?: Client, json?: unknown, raw?: string | Buffer, bearer?: string } = {}) {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    if (init.bearer) headers.set('authorization', `Bearer ${init.bearer}`)
    headers.set('x-real-ip', '192.0.2.10')
    let body = init.body
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    if (init.raw !== undefined) {
      headers.set('content-type', 'application/json')
      body = typeof init.raw === 'string' ? init.raw : new Uint8Array(init.raw)
    }
    const res = await fetch(`${base}${path}`, { ...init, headers, body })
    const text = await res.text()
    let data: unknown = text
    try {
      data = JSON.parse(text)
    }
    catch {
      // texte brut
    }
    return { status: res.status, data: data as Json }
  }
  const code = (res: { data: Json }) => res.data?.data?.code
  const upload = (projectId: string, doc: unknown, opts: { bearer?: string, client?: Client, query?: string } = { }) =>
    call(`/api/projects/${projectId}/results${opts.query ? `?${opts.query}` : ''}`, {
      method: 'POST', json: doc, ...(opts.client ? { client: opts.client } : { bearer: opts.bearer ?? token }),
    })

  async function newProject(slug: string, archived = false): Promise<string> {
    const res = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, profile_id, gate_id, default_branch, archived_at)
       VALUES ($1, $2, 'git', 'https://forge.exemple.test/acme/' || $1 || '.git', $3, $4, 'main', $5) RETURNING id`,
      [slug, `Projet ${slug}`, profileId, gateId, archived ? new Date() : null],
    )
    return res.rows[0]!.id
  }
  const scanCount = async (projectId: string) =>
    Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM scans WHERE project_id = $1', [projectId])).rows[0]!.n)

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-external-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '60000',
    }))
    void startConsole(async () => [])
    expect(await waitReady(30_000)).toBe(true)

    const app = createApp()
    app.use((await import('../../server/middleware/api-token')).default)
    app.use((await import('../../server/middleware/auth')).default)
    const router = createRouter()
    for (const r of apiRoutes()) router[r.method as 'get'](r.path, (await import(r.file)).default as EventHandler)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`

    gateId = (await db.pool.query<{ id: string }>('SELECT id FROM gates WHERE slug = \'defaut\'')).rows[0]!.id
    profileId = (await db.pool.query<{ id: string }>('SELECT id FROM profiles WHERE slug = \'complet\'')).rows[0]!.id
    projectA = await newProject('ext-alpha')
    projectB = await newProject('ext-beta')
    operator = await realLogin('xoperator', 'operator')
    viewer = await realLogin('xviewer', 'viewer')
    const tok = await call(`/api/projects/${projectA}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
    expect(tok.status, JSON.stringify(tok.data)).toBe(201)
    token = tok.data.value
  })

  // Connexion par l'API (cookie de session et jeton CSRF).
  async function realLogin(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client> {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const headers = new Headers({ 'content-type': 'application/json', 'x-real-ip': nextIp() })
    const res = await fetch(`${base}/api/auth/login`, { method: 'POST', headers, body: JSON.stringify({ username, password }) })
    expect(res.status).toBe(200)
    const data = await res.json() as Json
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
  }
  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  beforeEach(() => {
    tokenLimiter.reset('x')
    badTokenLimiter.reset('192.0.2.10')
  })

  it('SARIF valide par le jeton du projet : analyse externe, origine, gravités, verdict', async () => {
    const doc = sarif([
      result('ACME-1', 'src/app.js', { 'security-severity': '9.5' }),
      result('ACME-2', 'src/db.js', {}, 'warning'),
      result('ACME-3', 'src/x.js', { severity: 'bizarre' }),
    ])
    const res = await upload(projectA, doc, { query: 'ref=main' })
    expect(res.status, JSON.stringify(res.data)).toBe(201)
    expect(res.data).toMatchObject({ module: 'ext-acme-sast', results: 3, new: 3, verdict: 'failed', components: null })
    expect(res.data.source).toEqual({ tool: 'Acme SAST', version: '4.2.0', format: 'sarif', uploaded_via: 'api-token' })
    const scan = (await db.pool.query<Json>('SELECT * FROM scans WHERE id = $1', [res.data.scan_id])).rows[0]!
    expect(scan).toMatchObject({ trigger: 'external', status: 'done', verdict: 'failed', ref: 'main', plan: null })
    expect(scan.external_source).toEqual(res.data.source)
    expect(scan.verdict_details.reasons.some((r: Json) => r.code === 'sast' && r.blocking)).toBe(true)
    const mods = (await db.pool.query<Json>('SELECT module_id, module_version, status, results_count FROM scan_modules WHERE scan_id = $1', [scan.id])).rows
    expect(mods).toEqual([{ module_id: 'ext-acme-sast', module_version: '4.2.0', status: 'ok', results_count: 3 }])
    const f = (await db.pool.query<Json>('SELECT rule_id, severity, origin, category, tool FROM findings WHERE project_id = $1 ORDER BY rule_id', [projectA])).rows
    expect(f).toEqual([
      { rule_id: 'ACME-1', severity: 'critical', origin: 'external', category: 'sast', tool: 'ext-acme-sast' },
      { rule_id: 'ACME-2', severity: 'medium', origin: 'external', category: 'sast', tool: 'ext-acme-sast' },
      { rule_id: 'ACME-3', severity: 'medium', origin: 'external', category: 'sast', tool: 'ext-acme-sast' },
    ])
    // G5 : la table de gravités de l'outil externe est remplie et éditable.
    const maps = (await db.pool.query<Json>('SELECT native, severity FROM severity_maps WHERE module_id = \'ext-acme-sast\' ORDER BY native')).rows
    expect(maps.map(m => m.native)).toContain('security-severity:critical')
    // V4 : jamais de cache pour une analyse externe.
    expect(Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM result_cache')).rows[0]!.n)).toBe(0)
    // Audit.
    const audit = (await db.pool.query<Json>('SELECT action, outcome, details FROM audit_log WHERE action = \'scan.external\' ORDER BY id DESC LIMIT 1')).rows[0]!
    expect(audit).toMatchObject({ outcome: 'success', details: { module: 'ext-acme-sast', results: 3 } })
  })

  it('second envoi du même outil : rien de nouveau, et l\'appliance ne se compare jamais à une analyse externe', async () => {
    const project = await newProject('ext-gamma')
    const t = await call(`/api/projects/${project}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
    const doc = sarif([result('R1', 'a.js', { 'security-severity': '5.0' })], { name: 'Other Tool' })
    // Analyse de l'appliance terminée avant tout envoi, avec un résultat de module.
    const s1 = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, finished_at)
       VALUES ($1, 1, 'manual', 50, 'main', $2, $3, 'done', now()) RETURNING id`, [project, profileId, gateId])).rows[0]!.id
    const fm = (await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title)
       VALUES ($1, repeat('a', 64), 'gitleaks', 'g', 'secrets', 'high', 't') RETURNING id`, [project])).rows[0]!.id
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [s1, fm])

    const first = await upload(project, doc, { bearer: t.data.value })
    expect(first.status).toBe(201)
    expect(first.data.new).toBe(1)
    const second = await upload(project, doc, { bearer: t.data.value })
    expect(second.status).toBe(201)
    const isNew = (await db.pool.query<{ is_new: boolean }>('SELECT is_new FROM scan_findings WHERE scan_id = $1', [second.data.scan_id])).rows
    expect(isNew).toEqual([{ is_new: false }])

    // Analyse suivante de l'appliance : comparée à s1, pas à l'analyse externe.
    const s2 = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, started_at)
       VALUES ($1, 10, 'manual', 50, 'main', $2, $3, 'ingesting', now()) RETURNING id`, [project, profileId, gateId])).rows[0]!.id
    await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, 'gitleaks', '8', 'ok')`, [s2])
    await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true)', [s2, fm])
    await finalizeScanFindings(db.pool, s2, { complete: true })
    expect((await db.pool.query<{ is_new: boolean }>('SELECT is_new FROM scan_findings WHERE scan_id = $1', [s2])).rows).toEqual([{ is_new: false }])
    // Les résultats externes ne passent jamais « corrigés » par une analyse de l'appliance.
    expect((await db.pool.query<{ status: string }>(`SELECT status FROM findings WHERE project_id = $1 AND origin = 'external'`, [project])).rows)
      .toEqual([{ status: 'new' }])
  })

  it('SARIF sans résultat : verdict favorable', async () => {
    const res = await upload(projectA, sarif([], { name: 'Clean Tool', semanticVersion: '1.0.0' }))
    expect(res.status).toBe(201)
    expect(res.data).toMatchObject({ results: 0, verdict: 'passed', module: 'ext-clean-tool' })
  })

  it('CycloneDX 1.6 : SBOM rangé (F3), vulnérabilités en résultats externes', async () => {
    const doc = cdx('1.6', [{ id: 'CVE-2021-44906', ratings: [{ severity: 'critical' }], affects: [{ ref: 'pkg:npm/minimist@1.2.5' }] }])
    const res = await upload(projectA, doc)
    expect(res.status, JSON.stringify(res.data)).toBe(201)
    expect(res.data).toMatchObject({ module: 'ext-acme-sca', components: 2, results: 1, source: { format: 'cyclonedx', tool: 'Acme SCA', version: '9.1' } })
    const comps = (await db.pool.query<{ purl: string }>('SELECT purl FROM sbom_components WHERE scan_id = $1 ORDER BY purl', [res.data.scan_id])).rows
    expect(comps.map(c => c.purl)).toEqual(['pkg:npm/left-pad@1.3.0', 'pkg:npm/minimist@1.2.5'])
    const f = (await db.pool.query<Json>(`SELECT category, origin, vuln_ids FROM findings WHERE tool = 'ext-acme-sca'`)).rows
    expect(f).toEqual([{ category: 'sca', origin: 'external', vuln_ids: ['CVE-2021-44906'] }])
    expect((await upload(projectA, cdx('1.5'))).status).toBe(201)
  })

  it('documents invalides : refusés avec leurs défauts, rien ingéré', async () => {
    const before = await scanCount(projectA)
    const bad = await upload(projectA, { version: '2.0.0', runs: [{ tool: { driver: {} }, results: [{ ruleId: 'x' }] }] })
    expect(bad.status).toBe(422)
    expect(code(bad)).toBe('E_EXTERNAL_INVALID')
    expect(bad.data.data.issues).toEqual(expect.arrayContaining([
      { path: '/version', code: 'unsupported-version', detail: '2.0.0' },
      { path: '/runs/0/tool/driver/name', code: 'required' },
      { path: '/runs/0/results/0/message', code: 'required' },
    ]))
    const mixed = await upload(projectA, { version: '2.1.0', runs: [{ tool: { driver: { name: 'A' } }, results: [] }, { tool: { driver: { name: 'B' } }, results: [] }] })
    expect(mixed.status).toBe(422)
    expect(mixed.data.data.issues[0]).toMatchObject({ code: 'mixed-tools' })
    const oldCdx = await upload(projectA, cdx('1.4'))
    expect(oldCdx.status).toBe(422)
    expect(oldCdx.data.data.issues[0]).toMatchObject({ path: '/specVersion', code: 'unsupported-version' })
    const badComp = await upload(projectA, { ...cdx('1.6'), components: [42] })
    expect(badComp.status).toBe(422)
    const unknown = await upload(projectA, { hello: 'world' })
    expect(unknown.status).toBe(415)
    expect(code(unknown)).toBe('E_EXTERNAL_FORMAT')
    const truncated = await call(`/api/projects/${projectA}/results`, { method: 'POST', raw: JSON.stringify(sarif([])).slice(0, 40), bearer: token })
    expect(truncated.status).toBe(400)
    expect(code(truncated)).toBe('E_EXTERNAL_JSON')
    const empty = await call(`/api/projects/${projectA}/results`, { method: 'POST', raw: '', bearer: token })
    expect(empty.status).toBe(400)
    const tooMany = await upload(projectA, sarif(Array.from({ length: 10_001 }, (_, i) => result(`R${i}`, `f${i}.js`))))
    expect(tooMany.status).toBe(413)
    expect(code(tooMany)).toBe('E_EXTERNAL_TOO_MANY')
    const badQuery = await upload(projectA, sarif([]), { query: 'category=nope' })
    expect(badQuery.status).toBe(400)
    const badCommit = await upload(projectA, sarif([]), { query: 'commit=xyz' })
    expect(badCommit.status).toBe(400)
    expect(await scanCount(projectA)).toBe(before)
    const failed = (await db.pool.query<Json>('SELECT details FROM audit_log WHERE action = \'scan.external\' AND outcome = \'failure\' ORDER BY id DESC LIMIT 1')).rows[0]
    expect(failed?.details.code).toBeDefined()
  })

  it('document trop gros : refusé en flux (413)', async () => {
    const before = await scanCount(projectA)
    const big = Buffer.alloc(EXTERNAL_MAX_BYTES + 1024, 0x20)
    const res = await call(`/api/projects/${projectA}/results`, { method: 'POST', raw: big, bearer: token })
    expect(res.status).toBe(413)
    expect(code(res)).toBe('E_EXTERNAL_TOO_LARGE')
    expect(await scanCount(projectA)).toBe(before)
  })

  it('droits : autre projet, portée, rôles, projet archivé', async () => {
    const other = await upload(projectB, sarif([]))
    expect(other.status).toBe(403)
    expect(code(other)).toBe('E_TOKEN_SCOPE')
    const ro = await call(`/api/projects/${projectA}/tokens`, { method: 'POST', client: operator, json: { name: 'ro' } })
    await db.pool.query(`UPDATE api_tokens SET scopes = '{scan:read}' WHERE id = $1`, [ro.data.id])
    expect((await upload(projectA, sarif([]), { bearer: ro.data.value })).status).toBe(403)
    expect((await upload(projectA, sarif([]), { client: viewer })).status).toBe(403)
    const anonymous = await call(`/api/projects/${projectA}/results`, { method: 'POST', json: sarif([]) })
    expect(anonymous.status).toBe(401)
    const byOperator = await upload(projectB, sarif([]), { client: operator })
    expect(byOperator.status).toBe(201)
    expect(byOperator.data.source.uploaded_via).toBe('console')
    const archived = await newProject('ext-old', true)
    expect((await upload(archived, sarif([]), { client: operator })).status).toBe(409)
  })

  it('console : résultats filtrés par origine, source affichée ; analyse non rejouable', async () => {
    const ext = await call(`/api/findings?project_id=${projectA}&origin=external&status=new,confirmed,fixed&grouped=false`, { client: viewer })
    expect(ext.status).toBe(200)
    expect(ext.data.items.length).toBeGreaterThan(0)
    expect(ext.data.items.every((i: Json) => i.origin === 'external' && i.external_source?.tool)).toBe(true)
    const mod = await call(`/api/findings?project_id=${projectA}&origin=module`, { client: viewer })
    expect(mod.data.items).toEqual([])
    const scan = (await db.pool.query<{ id: string }>(`SELECT id FROM scans WHERE project_id = $1 AND trigger = 'external' LIMIT 1`, [projectA])).rows[0]!.id
    const detail = await call(`/api/scans/${scan}`, { client: viewer })
    expect(detail.status).toBe(200)
    expect(JSON.stringify(detail.data)).toContain('"external_source"')
    const replay = await call(`/api/scans/${scan}/replay`, { method: 'POST', client: operator })
    expect(replay.status).toBeGreaterThanOrEqual(400)
  })

  it('secret générique sans étiquette « secrets » : traité comme un secret, valeur jamais stockée (§ 6.3)', async () => {
    const project = await newProject('ext-secret')
    const t = await call(`/api/projects/${project}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    const value = Array.from({ length: 32 }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('')
    const leaky = {
      ruleId: 'generic-password',
      message: { text: `mot de passe en clair : ${value}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'conf/app.ini' }, region: { startLine: 2, snippet: { text: `password = ${value}` } } } }],
    }
    const other = { ...result('quality-rule', 'src/q.js'), message: { text: `identifiant ${value}` } }
    const res = await upload(project, sarif([leaky, other], { name: 'Home Detector' }), { bearer: t.data.value })
    expect(res.status, JSON.stringify(res.data)).toBe(201)
    const rows = (await db.pool.query<Json>('SELECT rule_id, category, title, message, snippet, secret_type FROM findings WHERE project_id = $1 ORDER BY rule_id', [project])).rows
    expect(rows.map(r => [r.rule_id, r.category])).toEqual([['generic-password', 'secrets'], ['quality-rule', 'sast']])
    expect(JSON.stringify(rows)).not.toContain(value)
    expect(rows[0]!.secret_type).toBeTruthy()
  })

  it('même outil, casse différente : même ligne de base (module ext-…, pas le nom brut)', async () => {
    const project = await newProject('ext-casse')
    const t = await call(`/api/projects/${project}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
    const doc = (name: string) => sarif([result('C1', 'c.js', { 'security-severity': '3.0' })], { name })
    expect((await upload(project, doc('Case Tool'), { bearer: t.data.value })).data.new).toBe(1)
    const second = await upload(project, doc('case tool'), { bearer: t.data.value })
    expect(second.data).toMatchObject({ module: 'ext-case-tool', new: 0 })
  })

  it('badge et « dernière analyse » : jamais un téléversement externe', async () => {
    const project = await newProject('ext-badge')
    const t = await call(`/api/projects/${project}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
    expect((await upload(project, sarif([], { name: 'Empty Tool' }), { bearer: t.data.value, query: 'ref=main' })).data.verdict).toBe('passed')
    expect(await latestVerdict(db.pool, project, 'main')).toBeNull()
    expect((await getProject(db.pool, project))?.last_scan ?? null).toBeNull()
  })

  it('un téléversement à la fois par projet : 429 E_EXTERNAL_BUSY, rien n\'est créé', async () => {
    const release = acquireExternalSlot(projectB)
    expect(release).toBeTypeOf('function')
    try {
      const before = await scanCount(projectB)
      const t = await call(`/api/projects/${projectB}/tokens`, { method: 'POST', client: operator, json: { name: 'ci' } })
      const res = await upload(projectB, sarif([]), { bearer: t.data.value })
      expect(res.status).toBe(429)
      expect(code(res)).toBe('E_EXTERNAL_BUSY')
      expect(await scanCount(projectB)).toBe(before)
      expect(acquireExternalSlot(projectB)).toBeNull()
    }
    finally {
      release!()
    }
    const again = acquireExternalSlot(projectB)
    expect(again).toBeTypeOf('function')
    again!()
  })

  it('client scanoria-scan upload : verdict et code de sortie', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'scanoria-upload-'))
    try {
      const failing = join(dir, 'failing.sarif')
      await writeFile(failing, JSON.stringify(sarif([result('CLI-1', 'cli.js', { 'security-severity': '9.0' })], { name: 'Cli Tool' })))
      const invalid = join(dir, 'invalid.json')
      await writeFile(invalid, JSON.stringify({ version: '2.1.0', runs: [] }))
      const env = { ...process.env, SCANORIA_TOKEN: token, SCANORIA_ALLOW_HTTP: '1', SCANORIA_INTERVAL: '1', SCANORIA_LANG: 'fr' }
      const client = (args: string[]) => run('sh', [CLIENT, ...args], { env, timeout: 60_000 })
        .then(r => ({ code: 0, ...r }))
        .catch((err: { code: number, stdout: string, stderr: string }) => ({ code: err.code, stdout: err.stdout, stderr: err.stderr }))
      const r = await client(['upload', failing, '--url', base, '--project', projectA, '--ref', 'release/1.0', '--tool-version', '2.0'])
      expect(r.code, r.stderr).toBe(1)
      expect(r.stdout).toContain('verdict : failed')
      const scan = (await db.pool.query<Json>(`SELECT ref, external_source FROM scans WHERE external_source->>'tool' = 'Cli Tool'`)).rows[0]!
      expect(scan).toMatchObject({ ref: 'release/1.0', external_source: { version: '2.0' } })
      const bad = await client(['upload', invalid, '--url', base, '--project', projectA])
      expect(bad.code).toBe(3)
      expect(bad.stderr).toContain('E_EXTERNAL_INVALID')
      expect(bad.stderr).toContain('/runs')
      expect((await client(['upload', join(dir, 'absent.sarif'), '--url', base, '--project', projectA])).code).toBe(3)
      expect(`${r.stdout}${r.stderr}${bad.stderr}`).not.toContain(token)
    }
    finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
