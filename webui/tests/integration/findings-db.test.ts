// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D contre un vrai PostgreSQL 16 : ingestion (contrat 5), cycle
// nouveau → corrigé → réapparu, nouveau code, couverture (G15), gravités
// éditables (G5), tri, secrets (F7), exceptions et paquets malveillants (H4).

import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { createUser } from '../../server/utils/users'
import { finalizeScanFindings, ingestModuleOutputs, readOutput } from '../../server/findings/ingest'
import { applyApprovedAcceptance, findingsSummary, getFinding, listFindings, setFindingStatus, setSecretState, TriageError } from '../../server/findings/triage'
import { decideException, ExceptionError, isoDay, listExceptions, requestException, revokeException } from '../../server/findings/exceptions'
import { listSeverityMaps, updateSeverityMap } from '../../server/findings/severity'
import { readModuleHints } from '../../server/findings/manifest'
import { gapsFromDetection, mergeCoverageGaps } from '../../server/findings/coverage'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))

describe.skipIf(!DATABASE_URL)('résultats unifiés (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let userId: number
  let adminId: number
  let scanNo = 0

  /** 0.7 : une exception est demandée (ops), puis approuvée par un autre administrateur. */
  async function createException(db0: TestDatabase['pool'], e: { project_id: string, kind: string, target: Record<string, unknown>, reason: string, expires_on: string }, requester: number) {
    const req = await requestException(db0, { ...e, requested_via: 'console', requester_label: 'ops', requester_is_human: true, requester_user_id: requester, commit_authors: [] })
    return decideException(db0, req.id, { decision: 'approved', reason: 'approuvée pour le test', deciderUserId: adminId, ip: null })
  }
  const jobs = new Map<string, string>()

  async function newScan(opts: { ref?: string, modules?: string[], commit?: string } = {}): Promise<string> {
    scanNo++
    const jobId = crypto.randomUUID()
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, job_id, started_at)
       VALUES ($1, $2, 'manual', 50, $3, $4, (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', $5, now())
       RETURNING id`,
      [projectId, scanNo, opts.ref ?? 'main', opts.commit ?? randomBytes(20).toString('hex'), jobId],
    )
    const id = r.rows[0]!.id
    jobs.set(id, jobId)
    for (const m of opts.modules ?? ['gitleaks', 'osv-scanner', 'trivy']) {
      await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '1.0.0', 'ok')`, [id, m])
    }
    return id
  }

  async function done(scanId: string) {
    await db.pool.query(`UPDATE scans SET status = 'done', finished_at = now() WHERE id = $1`, [scanId])
  }

  /** Dépose un SARIF dans results/<job>/<module>/result.sarif. */
  async function output(scanId: string, moduleId: string, doc: unknown): Promise<{ resultDir: string, rel: string }> {
    const resultDir = join(root, 'scans', 'results', jobs.get(scanId)!)
    await mkdir(join(resultDir, moduleId), { recursive: true })
    await writeFile(join(resultDir, moduleId, 'result.sarif'), JSON.stringify(doc))
    return { resultDir, rel: `${moduleId}/result.sarif` }
  }

  async function ingest(scanId: string, moduleId: string, doc: unknown) {
    const { resultDir, rel } = await output(scanId, moduleId, doc)
    return ingestModuleOutputs(db.pool, { scanId, moduleId, resultDir, outputs: { sarif: rel } })
  }

  const recorded = async (id: string) => JSON.parse(await readFile(`${MODULES}${id}/tests/recorded.sarif`, 'utf8')) as Record<string, unknown>

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-findings-'))
    process.env.SCANORIA_SCANS_DIR = join(root, 'scans')
    const index = {
      schema: 1, version: 1,
      modules: [
        { id: 'gitleaks', version: '1.0.0', categories: ['secrets'] },
        { id: 'osv-scanner', version: '1.0.0', categories: ['sca'], scan: { severity_map: { 'security-severity:critical': 'high' } } },
        { id: 'trivy', version: '1.0.0', categories: ['sca', 'iac', 'container', 'sbom', 'secrets'] },
        { id: 'trivy', version: '0.9.0', categories: ['sca'] },
      ],
    }
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify(index))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    userId = Number((await createUser(db.pool, { username: 'ops', role: 'operator', password: 'ops-long-password' })).id)
    adminId = Number((await createUser(db.pool, { username: 'chef', role: 'admin', password: 'chef-long-password' })).id)
    const p = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, profile_id, gate_id, detection)
       VALUES ('demo', 'Démo', 'git', 'https://forge.exemple.test/demo.git', (SELECT id FROM profiles WHERE slug = 'rapide'),
               (SELECT id FROM gates WHERE slug = 'defaut'), $1) RETURNING id`,
      [JSON.stringify({ version: 1, languages: ['javascript', 'shell'], package_managers: [{ name: 'npm', manifest: 'package.json', lockfile: 'package-lock.json' }, { name: 'pip', manifest: 'api/requirements.in', lockfile: null }], missing_lockfiles: ['api/requirements.in', 'tools/package.json'] })],
    )
    projectId = p.rows[0]!.id
  })

  afterAll(async () => {
    delete process.env.SCANORIA_SCANS_DIR
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('premier passage : tout est nouveau, gravités du manifeste, secrets et paquets', async () => {
    const s1 = await newScan()
    const g = await ingest(s1, 'gitleaks', await recorded('gitleaks'))
    expect(g).toEqual({ count: 3, newCount: 3, errors: [] })
    const o = await ingest(s1, 'osv-scanner', await recorded('osv-scanner'))
    expect(o.count).toBe(1)
    const t = await ingest(s1, 'trivy', await recorded('trivy'))
    expect(t.count).toBe(5)
    // Rejeu de l'ingestion (relance) : aucun doublon.
    expect((await ingest(s1, 'trivy', await recorded('trivy'))).newCount).toBe(0)
    const fin = await finalizeScanFindings(db.pool, s1, { complete: true })
    expect(fin).toMatchObject({ total: 9, newCount: 9, fixedCount: 0 })
    await done(s1)

    const all = await listFindings(db.pool, { limit: 50, offset: 0 })
    expect(all.total).toBe(9)
    expect(all.items.every(f => f.is_new && f.status === 'new')).toBe(true)
    // Tri : gravité décroissante.
    expect(all.items[0]!.severity).toBe('critical')
    const osv = all.items.find(f => f.tool === 'osv-scanner')!
    expect(osv.severity).toBe('high') // scan.severity_map du manifeste
    const secrets = await listFindings(db.pool, { limit: 50, offset: 0, secret: true })
    expect(secrets.total).toBe(3)
    expect(secrets.items.every(f => f.secret_state === 'to-revoke' && f.category === 'secrets')).toBe(true)
    const maps = await db.pool.query('SELECT module_id, native, severity, builtin FROM severity_maps ORDER BY 1, 2')
    expect(maps.rows).toContainEqual({ module_id: 'osv-scanner', native: 'security-severity:critical', severity: 'high', builtin: true })
    expect(maps.rows).toContainEqual({ module_id: 'trivy', native: 'critical', severity: 'critical', builtin: true })
  })

  it('le secret factice du banc d\'essai gitleaks n\'apparaît nulle part en base', async () => {
    const env = await readFile(`${MODULES}gitleaks/testbed/.env`, 'utf8')
    const values = env.split('\n').filter(l => /^[A-Z_]+=/.test(l)).map(l => l.slice(l.indexOf('=') + 1).trim())
    const doc = await recorded('gitleaks') as { runs: { results: { message: { text: string }, locations: { physicalLocation: { region: { snippet: { text: string } } } }[] }[] }[] }
    doc.runs[0]!.results.forEach((r, i) => {
      r.locations[0]!.physicalLocation.region.snippet.text = `API_KEY=${values[i % values.length]}`
      r.message.text = `leak ${values[i % values.length]}`
    })
    const s = await newScan({ ref: 'secret-test', modules: ['gitleaks'] })
    await ingest(s, 'gitleaks', doc)
    await finalizeScanFindings(db.pool, s, { complete: true })
    const dump = await db.pool.query(`SELECT string_agg(f::text, ' ') AS all FROM findings f`)
    const audit = await db.pool.query(`SELECT coalesce(string_agg(a::text, ' '), '') AS all FROM audit_log a`)
    const scans = await db.pool.query(`SELECT string_agg(s::text, ' ') AS all FROM scans s`)
    for (const v of values) {
      expect(dump.rows[0].all).not.toContain(v)
      expect(audit.rows[0].all).not.toContain(v)
      expect(scans.rows[0].all).not.toContain(v)
    }
    await db.pool.query('DELETE FROM findings WHERE first_scan_id = $1', [s])
  })

  it('cycle nouveau → corrigé → réapparu, nouveau code relatif à la branche', async () => {
    // Deuxième analyse de main : trivy ne voit plus DS-0026 ; rien de nouveau.
    const s2 = await newScan()
    const tri = await recorded('trivy') as { runs: { results: { ruleId: string }[] }[] }
    tri.runs[0]!.results = tri.runs[0]!.results.filter(r => r.ruleId !== 'DS-0026')
    await ingest(s2, 'gitleaks', await recorded('gitleaks'))
    await ingest(s2, 'osv-scanner', await recorded('osv-scanner'))
    await ingest(s2, 'trivy', tri)
    const fin = await finalizeScanFindings(db.pool, s2, { complete: true })
    expect(fin).toMatchObject({ total: 8, newCount: 0, fixedCount: 1 })
    await done(s2)
    const fixed = await listFindings(db.pool, { limit: 50, offset: 0, status: ['fixed'] })
    expect(fixed.items.map(f => f.rule_id)).toEqual(['DS-0026'])
    expect((await listFindings(db.pool, { limit: 50, offset: 0, is_new: true, project_id: projectId })).total).toBe(0)

    // Analyse incomplète d'une autre branche sans DS-0002 : rien n'est corrigé.
    const other = await newScan({ ref: 'feature', modules: ['trivy'] })
    const tri2 = await recorded('trivy') as { runs: { results: { ruleId: string }[] }[] }
    tri2.runs[0]!.results = tri2.runs[0]!.results.filter(r => r.ruleId !== 'DS-0002')
    await ingest(other, 'trivy', tri2)
    expect((await finalizeScanFindings(db.pool, other, { complete: false })).fixedCount).toBe(0)
    // Première analyse de cette branche : tout y est nouveau.
    expect((await db.pool.query('SELECT count(*)::int AS n FROM scan_findings WHERE scan_id = $1 AND is_new', [other])).rows[0].n).toBe(4)
    await done(other)

    // Faux positif conservé même absent ; DS-0026 réapparaît → nouveau.
    const ds25 = (await listFindings(db.pool, { limit: 1, offset: 0, q: 'DS-0025' })).items[0]!
    await setFindingStatus(db.pool, ds25.id, { status: 'false-positive', reason: 'image de test' }, userId)
    const s3 = await newScan()
    const tri3 = await recorded('trivy') as { runs: { results: { ruleId: string }[] }[] }
    tri3.runs[0]!.results = tri3.runs[0]!.results.filter(r => r.ruleId !== 'DS-0025')
    await ingest(s3, 'gitleaks', await recorded('gitleaks'))
    await ingest(s3, 'osv-scanner', await recorded('osv-scanner'))
    await ingest(s3, 'trivy', tri3)
    const fin3 = await finalizeScanFindings(db.pool, s3, { complete: true })
    expect(fin3).toMatchObject({ newCount: 1, fixedCount: 0 })
    await done(s3)
    const ds26 = (await listFindings(db.pool, { limit: 1, offset: 0, q: 'DS-0026' })).items[0]!
    expect(ds26).toMatchObject({ status: 'new', is_new: true })
    expect((await getFinding(db.pool, ds25.id))!.status).toBe('false-positive')
    // Filtre par analyse.
    expect((await listFindings(db.pool, { limit: 50, offset: 0, scan_id: s3 })).total).toBe(8)
  })

  it('croisement de branches : un résultat vu sur une PR puis corrigé sur main passe « corrigé »', async () => {
    const rule = { version: '2.1.0', runs: [{ tool: { driver: { name: 's' } }, results: [{ ruleId: 'xbranch', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'x.js' }, region: { startLine: 1, snippet: { text: 'eval(x)' } } } }] }] }] }
    const empty = { version: '2.1.0', runs: [{ tool: { driver: { name: 's' } }, results: [] }] }
    const m1 = await newScan({ ref: 'xmain', modules: ['semgrep'] })
    await ingest(m1, 'semgrep', rule)
    await finalizeScanFindings(db.pool, m1, { complete: true })
    await done(m1)
    const pr = await newScan({ ref: 'xpr', modules: ['semgrep'] })
    await ingest(pr, 'semgrep', rule)
    await finalizeScanFindings(db.pool, pr, { complete: true })
    await done(pr)
    const m2 = await newScan({ ref: 'xmain', modules: ['semgrep'] })
    await ingest(m2, 'semgrep', empty)
    expect((await finalizeScanFindings(db.pool, m2, { complete: true })).fixedCount).toBe(1)
    await done(m2)
    expect((await listFindings(db.pool, { limit: 1, offset: 0, q: 'xbranch' })).items[0]!.status).toBe('fixed')
  })

  it('sortie illisible : rien n\'est déclaré « corrigé », la couverture le signale', async () => {
    const rule = { version: '2.1.0', runs: [{ tool: { driver: { name: 's' } }, results: [{ ruleId: 'unread', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'y.js' }, region: { startLine: 1, snippet: { text: 'eval(y)' } } } }] }] }] }
    const a = await newScan({ ref: 'unread', modules: ['semgrep'] })
    await ingest(a, 'semgrep', rule)
    await finalizeScanFindings(db.pool, a, { complete: true })
    await done(a)
    const b = await newScan({ ref: 'unread', modules: ['semgrep'] })
    const dir = join(root, 'scans', 'results', jobs.get(b)!)
    await mkdir(dir, { recursive: true })
    await writeFile(join(dir, 'bad.sarif'), '{')
    const res = await ingestModuleOutputs(db.pool, { scanId: b, moduleId: 'semgrep', resultDir: dir, outputs: { sarif: 'bad.sarif' } })
    expect(res.errors).toEqual([{ code: 'invalid-json', output: 'sarif' }])
    expect((await finalizeScanFindings(db.pool, b, { complete: true })).fixedCount).toBe(0)
    const cov = (await db.pool.query('SELECT coverage FROM scans WHERE id = $1', [b])).rows[0].coverage
    expect(cov.gaps).toContainEqual({ kind: 'output-error', module: 'semgrep', code: 'invalid-json' })
    await done(b)
  })

  it('couverture (G15) : fichiers ignorés, langages sans module, verrouillage absent, entrées de C conservées', async () => {
    const s = await newScan({ modules: ['gitleaks'] })
    await db.pool.query(`UPDATE scans SET coverage = '{"gaps":[{"kind":"category","category":"sast"}],"profile":"rapide"}' WHERE id = $1`, [s])
    const dir = join(root, 'scans', 'results', jobs.get(s)!)
    await mkdir(dir, { recursive: true })
    await writeFile(join(dir, 'result.json'), JSON.stringify({ source: { skipped: [{ path: 'big.bin', reason: 'size' }, { path: 'l', reason: 'symlink' }, { path: 'm', reason: 'size' }] } }))
    const fin = await finalizeScanFindings(db.pool, s, { complete: false })
    expect(fin.coverage).toEqual([
      { kind: 'skipped-files', count: 3, reasons: { size: 2, symlink: 1 }, sample: ['big.bin', 'l', 'm'] },
      { kind: 'language-without-module', language: 'javascript' },
      { kind: 'language-without-module', language: 'shell' },
      { kind: 'lockfile-missing', manifest: 'api/requirements.in', manager: 'pip' },
      { kind: 'lockfile-missing', manifest: 'tools/package.json', manager: null },
    ])
    // Idempotent ; l'entrée de C et les autres clés sont gardées.
    await finalizeScanFindings(db.pool, s, { complete: false })
    const cov = (await db.pool.query('SELECT coverage FROM scans WHERE id = $1', [s])).rows[0].coverage
    expect(cov.profile).toBe('rapide')
    expect(cov.gaps).toHaveLength(6)
    expect(cov.gaps[0]).toEqual({ kind: 'category', category: 'sast' })
    await mergeCoverageGaps(db.pool, s, [{ kind: 'output-truncated', module: 'a' }], ['output-truncated'], 'a')
    await mergeCoverageGaps(db.pool, s, [{ kind: 'output-truncated', module: 'a' }], ['output-truncated'], 'a')
    expect((await db.pool.query('SELECT coverage FROM scans WHERE id = $1', [s])).rows[0].coverage.gaps).toHaveLength(7)
    expect(gapsFromDetection(null, new Set())).toEqual([])
    expect(gapsFromDetection({ languages: [{ name: 'python' }, '<bad>'] }, new Set(['sast']))).toEqual([])
  })

  it('sorties illisibles, chemins piégés, liens symboliques, JSON invalide', async () => {
    const s = await newScan({ modules: ['trivy'] })
    const dir = join(root, 'scans', 'results', jobs.get(s)!)
    await mkdir(join(dir, 'm'), { recursive: true })
    await writeFile(join(dir, 'm', 'bad.json'), '{')
    await writeFile(join(root, 'outside.sarif'), '{}')
    await symlink(join(root, 'outside.sarif'), join(dir, 'm', 'link.sarif'))
    expect((await readOutput(dir, '../outside.sarif')).error?.code).toBe('output-path')
    expect((await readOutput(dir, 'm/link.sarif')).error?.code).toBe('output-path')
    expect((await readOutput(dir, 'm/bad.json')).error?.code).toBe('invalid-json')
    expect((await readOutput(dir, 'm/absent.sarif')).error?.code).toBe('output-unreadable')
    expect((await readOutput(join(root, 'nope'), 'a')).error?.code).toBe('output-unreadable')
    expect((await readOutput(dir, 'm')).error?.code).toBe('output-unreadable')
    const res = await ingestModuleOutputs(db.pool, { scanId: s, moduleId: 'trivy', resultDir: dir, outputs: { sarif: 'm/link.sarif', cyclonedx: 'm/bad.json' } })
    expect(res).toEqual({ count: 0, newCount: 0, errors: [{ code: 'output-path', output: 'sarif' }, { code: 'invalid-json', output: 'cyclonedx' }] })
    await expect(ingestModuleOutputs(db.pool, { scanId: crypto.randomUUID(), moduleId: 'x', resultDir: dir, outputs: {} })).rejects.toThrow(/scan not found/)
  })

  it('sortie tronquée signalée dans la couverture ; CycloneDX', async () => {
    const s = await newScan({ modules: ['grype'] })
    const many = { version: '2.1.0', runs: [{ tool: { driver: { name: 'g' } }, results: Array.from({ length: 10_001 }, (_, i) => ({ ruleId: 'r', message: { text: 'x' }, locations: [{ physicalLocation: { artifactLocation: { uri: `f${i}` } } }] })) }] }
    const res = await ingest(s, 'grype', many)
    expect(res.count).toBe(10_000)
    expect(res.errors).toContainEqual({ code: 'truncated', output: 'sarif', detail: '10001' })
    expect((await db.pool.query('SELECT coverage FROM scans WHERE id = $1', [s])).rows[0].coverage.gaps).toEqual([{ kind: 'output-truncated', module: 'grype' }])
    const dir = join(root, 'scans', 'results', jobs.get(s)!)
    await writeFile(join(dir, 'bom.json'), JSON.stringify({ bomFormat: 'CycloneDX', components: [{ 'bom-ref': 'a', 'purl': 'pkg:npm/evil@1.0.0' }], vulnerabilities: [{ id: 'MAL-2025-42', affects: [{ ref: 'a' }] }] }))
    const cdx = await ingestModuleOutputs(db.pool, { scanId: s, moduleId: 'grype', resultDir: dir, outputs: { cyclonedx: 'bom.json' } })
    expect(cdx.count).toBe(1)
    await db.pool.query(`DELETE FROM findings WHERE tool = 'grype' AND NOT malicious`)
  })

  it('H4 : un paquet malveillant ne peut être ni accepté ni exempté', async () => {
    const mal = (await listFindings(db.pool, { limit: 5, offset: 0, malicious: true })).items[0]!
    expect(mal.vuln_ids).toEqual(['MAL-2025-42'])
    // « accepted » ne se pose plus par le tri direct (seulement par une exception approuvée) ; jamais pour H4.
    await expect(setFindingStatus(db.pool, mal.id, { status: 'accepted' as never, reason: 'r' }, userId)).rejects.toThrow(TriageError)
    expect(await applyApprovedAcceptance(db.pool, mal.id, { until: isoDay(10), reason: 'r', deciderId: userId })).toBeNull()
    await expect(setFindingStatus(db.pool, mal.id, { status: 'false-positive', reason: 'r' }, userId)).rejects.toThrow('E_MALICIOUS')
    await setFindingStatus(db.pool, mal.id, { status: 'confirmed' }, userId)
    await expect(createException(db.pool, { project_id: projectId, kind: 'rule', target: { rule_id: 'MAL-2025-42' }, reason: 'non', expires_on: isoDay(10) }, userId)).rejects.toThrow('E_MALICIOUS')
    await db.pool.query(`UPDATE findings SET secret_type = 'x', secret_state = 'to-revoke' WHERE id = $1`, [mal.id])
    await expect(setSecretState(db.pool, mal.id, 'false-positive', userId)).rejects.toThrow('E_MALICIOUS')
    await db.pool.query(`UPDATE findings SET secret_type = NULL, secret_state = NULL WHERE id = $1`, [mal.id])
    await expect(createException(db.pool, { project_id: projectId, kind: 'finding', target: { finding_id: mal.id }, reason: 'non', expires_on: isoDay(10) }, userId)).rejects.toThrow('E_MALICIOUS')
    await expect(createException(db.pool, { project_id: projectId, kind: 'vuln', target: { vuln_id: 'MAL-2025-42' }, reason: 'non', expires_on: isoDay(10) }, userId)).rejects.toThrow(ExceptionError)
    const summary = await findingsSummary(db.pool)
    expect(summary[0]).toMatchObject({ project_slug: 'demo', malicious: 1, secrets_to_revoke: 3 })
  })

  it('tri : acceptation datée (posée par l\'approbation), échue → nouveau ; secrets révoqués ou faux positifs avec auteur', async () => {
    const vuln = (await listFindings(db.pool, { limit: 1, offset: 0, tool: 'osv-scanner' })).items[0]!
    await expect(setFindingStatus(db.pool, vuln.id, { status: 'accepted' as never, reason: 'x' }, userId)).rejects.toThrow('E_VALIDATION')
    await applyApprovedAcceptance(db.pool, vuln.id, { reason: 'correctif en cours', until: isoDay(30), deciderId: userId })
    let d = (await getFinding(db.pool, vuln.id))!
    expect(d).toMatchObject({ status: 'accepted', status_reason: 'correctif en cours', status_until: isoDay(30), status_by: 'ops', accepted_expired: false })
    await db.pool.query(`UPDATE findings SET status_until = current_date - 1 WHERE id = $1`, [vuln.id])
    d = (await getFinding(db.pool, vuln.id))!
    expect(d).toMatchObject({ status: 'new', accepted_expired: true })
    expect((await listFindings(db.pool, { limit: 50, offset: 0, status: ['accepted'] })).items.find(f => f.id === vuln.id)).toBeUndefined()

    const [a, b] = (await listFindings(db.pool, { limit: 5, offset: 0, secret: true })).items
    expect((await getFinding(db.pool, a!.id))!.revoke_pending_days).toBe(0)
    await setSecretState(db.pool, a!.id, 'revoked', userId)
    await setSecretState(db.pool, b!.id, 'false-positive', userId)
    const ra = (await getFinding(db.pool, a!.id))!
    const rb = (await getFinding(db.pool, b!.id))!
    expect(ra).toMatchObject({ secret_state: 'revoked', secret_state_by: 'ops', revoke_pending_days: null })
    expect(ra.secret_state_at).toMatch(/Z$/)
    expect(rb).toMatchObject({ secret_state: 'false-positive', status: 'false-positive' })
    await setSecretState(db.pool, b!.id, 'to-revoke', userId)
    expect((await getFinding(db.pool, b!.id))!.status).toBe('new')
    await expect(setSecretState(db.pool, vuln.id, 'revoked', userId)).rejects.toThrow('E_NOT_SECRET')
    await expect(setSecretState(db.pool, crypto.randomUUID(), 'revoked', userId)).rejects.toThrow('E_NOT_FOUND')
    expect(await getFinding(db.pool, crypto.randomUUID())).toBeNull()
  })

  it('exceptions : datées, au plus un an, révocables, échues inactives', async () => {
    const e = await createException(db.pool, { project_id: projectId, kind: 'path', target: { glob: 'tests/**' }, reason: 'jeux de test', expires_on: isoDay(30) }, userId)
    expect(e).toMatchObject({ kind: 'path', active: true, expired: false, created_by: 'ops', target: { glob: 'tests/**' } })
    await expect(createException(db.pool, { project_id: projectId, kind: 'rule', target: { rule_id: 'x' }, reason: 'trop long', expires_on: isoDay(400) }, userId)).rejects.toThrow('E_VALIDATION')
    await expect(createException(db.pool, { project_id: projectId, kind: 'rule', target: { rule_id: 'x' }, reason: 'passé', expires_on: isoDay(-1) }, userId)).rejects.toThrow('E_VALIDATION')
    await expect(createException(db.pool, { project_id: projectId, kind: 'rule', target: { rule_id: 'x' }, reason: 'date', expires_on: '2026-02-31' }, userId)).rejects.toThrow('E_VALIDATION')
    await expect(createException(db.pool, { project_id: crypto.randomUUID(), kind: 'rule', target: { rule_id: 'x' }, reason: 'inconnu', expires_on: isoDay(1) }, userId)).rejects.toThrow('E_NOT_FOUND')
    await expect(createException(db.pool, { project_id: projectId, kind: 'finding', target: { finding_id: crypto.randomUUID() }, reason: 'inconnu', expires_on: isoDay(1) }, userId)).rejects.toThrow('E_NOT_FOUND')
    const old = await createException(db.pool, { project_id: projectId, kind: 'vuln', target: { vuln_id: 'CVE-2021-44906' }, reason: 'échue', expires_on: isoDay(0) }, userId)
    await db.pool.query(`UPDATE exceptions SET expires_on = current_date - 1 WHERE id = $1`, [old.id])
    expect((await listExceptions(db.pool, projectId, false)).map(x => x.id)).toEqual([e.id])
    const revoked = await revokeException(db.pool, e.id, userId)
    expect(revoked).toMatchObject({ active: false, revoked_by: 'ops' })
    expect(await listExceptions(db.pool, projectId, false)).toEqual([])
    expect((await listExceptions(db.pool, projectId, true)).find(x => x.id === old.id)).toMatchObject({ expired: true })
    await expect(revokeException(db.pool, crypto.randomUUID(), userId)).rejects.toThrow('E_NOT_FOUND')
  })

  it('gravités (G5) : modification, valeur d\'origine, retour au défaut, appliquée à l\'analyse suivante', async () => {
    const hints = await readModuleHints('trivy')
    expect(hints.categories).toContain('iac')
    expect((await readModuleHints('trivy', '0.9.0')).categories).toEqual(['sca'])
    expect(await readModuleHints('absent')).toEqual({ categories: [], severityMap: null })
    expect(await readModuleHints('trivy', null, join(root, 'missing.json'))).toEqual({ categories: [], severityMap: null })

    const changed = await updateSeverityMap(db.pool, 'trivy', 'low', 'medium', userId, null)
    expect(changed).toEqual({ before: 'low', after: 'medium' })
    expect(await updateSeverityMap(db.pool, 'trivy', 'nope', 'high', userId, null)).toBeNull()
    const rows = await listSeverityMaps(db.pool, async id => (await readModuleHints(id)).severityMap)
    expect(rows.find(r => r.module_id === 'trivy' && r.native === 'low')).toMatchObject({ severity: 'medium', origin: 'low', builtin: false, updated_by: 'ops' })
    expect(rows.find(r => r.module_id === 'osv-scanner')).toMatchObject({ severity: 'high', origin: 'high' })

    const s = await newScan()
    await ingest(s, 'trivy', await recorded('trivy'))
    const ds26 = (await listFindings(db.pool, { limit: 1, offset: 0, q: 'DS-0026' })).items[0]!
    expect(ds26.severity).toBe('medium')
    expect(await updateSeverityMap(db.pool, 'trivy', 'low', null, userId, null)).toEqual({ before: 'medium', after: 'low' })
  })
})
