// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.6, chantier D, contre un vrai PostgreSQL 16 et un faux runner :
// - V3/V5 : plan rangé par durée mesurée, graphe SBOM, tâche avec « after » et « cache » ;
// - V4 : sortie rangée sous sa clé, reprise ingérée comme neuve (reused_from,
//   compteur), analyse d'essai exclue, éviction ;
// - V6 : module « not-applicable » enregistré, couverture, analyse complète ;
// - rejeu G11 à l'identique.

import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { VerdictDetails } from '#shared/analysis'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadWorkerConfig, type WorkerConfig } from '../../server/scans/config'
import { enqueueScan } from '../../server/scans/enqueue'
import { pendingGate, type Integrations } from '../../server/scans/integrations'
import { ScanWorker } from '../../server/scans/worker'
import { getScan } from '../../server/scans/api'
import type { ScanJob } from '../../server/scans/contract'
import { parsePlan } from '../../server/scans/plan'
import { purgeCache } from '../../server/scans/orchestration'
import { purgeResultCache } from '../../server/scans/result-cache'

const COMMIT = 'c'.repeat(40)
const DIGEST = `sha256:${'d'.repeat(64)}`
const OLD_DIGEST = `sha256:${'e'.repeat(64)}`
const TREE = 'a'.repeat(64)
const key = (c: string) => c.repeat(64)

type ModuleOver = { status?: string, cache_key?: string, reused_from?: string, sbom_fallback?: boolean, input?: 'src' | 'sbom', duration?: number }

describe.skipIf(!DATABASE_URL)('orchestration des analyses (V3–V6, PostgreSQL réel, faux runner)', () => {
  let db: TestDatabase
  let root: string
  let cfg: WorkerConfig
  let cacheDir: string
  let paths: { modulesStateFile: string, catalogIndexFile: string }
  let complet: string
  let gate: string
  const ingested: { scanId: string, moduleId: string, outputs: Record<string, string>, sarif: string }[] = []
  const finalized: [string, boolean][] = []

  const integrations: Integrations = {
    decryptSecret: async () => {
      throw new Error('none')
    },
    ingestModuleOutputs: async (_db, args) => {
      const sarif = await readFile(join(args.resultDir, args.outputs.sarif ?? args.outputs.cyclonedx!), 'utf8')
      ingested.push({ scanId: args.scanId, moduleId: args.moduleId, outputs: args.outputs, sarif })
      return { count: 2, newCount: 1, errors: [] }
    },
    ingestSbomOutput: async () => {},
    finalizeScanFindings: async (_db, scanId, { complete }) => {
      finalized.push([scanId, complete])
    },
    evaluateGate: async (pool, scanId) => ({ ...(await pendingGate(pool, scanId)), verdict: 'passed' as VerdictDetails['verdict'] }),
    enqueueAiTask: async () => null,
    runProjectSchedules: async () => {},
  }
  const worker = () => new ScanWorker(db.pool, cfg, paths, integrations, () => {})

  async function newProject(): Promise<string> {
    const slug = `p-${randomUUID().slice(0, 8)}`
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, default_branch, profile_id, gate_id)
       VALUES ($1, $1, 'git', $2, 'main', $3, $4) RETURNING id`, [slug, `https://forge.exemple.test/exemple/${slug}.git`, complet, gate])
    return r.rows[0]!.id
  }

  async function takeJob(jobId: string): Promise<ScanJob> {
    const path = join(cfg.scansDir, 'jobs', 'incoming', `${jobId}.json`)
    const job = JSON.parse(await readFile(path, 'utf8')) as ScanJob
    await rm(path)
    return job
  }

  /** Faux runner : sorties SARIF écrites, mesures et champs 0.6 au choix. */
  async function runJob(jobId: string, over: Record<string, ModuleOver> = {}): Promise<ScanJob> {
    const job = await takeJob(jobId)
    const dir = join(cfg.scansDir, 'results', jobId)
    await mkdir(dir, { recursive: true })
    const modules = []
    for (const m of job.modules) {
      const o = over[m.id] ?? {}
      const status = o.status ?? 'ok'
      const kind = m.id === 'syft' ? 'cyclonedx' : 'sarif'
      const file = kind === 'cyclonedx' ? 'sbom.cdx.json' : 'result.sarif'
      await mkdir(join(dir, m.id), { recursive: true })
      if (status === 'ok') await writeFile(join(dir, m.id, file), JSON.stringify({ tool: m.id, reused: !!o.reused_from }))
      modules.push({
        id: m.id, version: m.version, status, error: null, image_digest: DIGEST,
        feeds: [], started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:00:05Z', exit_code: status === 'ok' ? 0 : null,
        outputs: status === 'ok' ? { [kind]: `${m.id}/${file}` } : {}, log: null,
        ...(o.reused_from || status !== 'ok' ? {} : { stats: { duration_ms: o.duration ?? 5000 } }),
        ...(o.cache_key ? { cache_key: o.cache_key } : {}),
        ...(o.reused_from ? { reused_from: o.reused_from } : {}),
        ...(o.input ? { input: o.input } : {}),
        ...(o.sbom_fallback ? { sbom_fallback: true } : {}),
      })
    }
    await writeFile(join(dir, 'result.json'), JSON.stringify({
      schema: 1, id: job.id, scan_id: job.scan_id, status: 'ok', error: null,
      started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:01:00Z',
      source: { kind: 'git', commit: COMMIT, history: 'shallow', files: 12, bytes: 3456, skipped: [], tree: TREE, detection: { 'python': 3, 'containers': 1, 'Bad Key': 2 } },
      modules,
    }))
    return job
  }

  async function dispatched(scanId: string): Promise<string> {
    expect(await worker().dispatchOne()).toBe('dispatched')
    return (await db.pool.query<{ job_id: string }>('SELECT job_id FROM scans WHERE id = $1', [scanId])).rows[0]!.job_id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-cache-'))
    for (const d of ['scans/jobs/tmp', 'scans/jobs/incoming', 'scans/results', 'logs']) await mkdir(join(root, d), { recursive: true })
    cacheDir = join(root, 'result-cache')
    process.env.SCANORIA_RESULT_CACHE = cacheDir
    cfg = { ...loadWorkerConfig({}), scansDir: join(root, 'scans'), runnerStateFile: join(root, 'runner.json'), scanLogsDir: join(root, 'logs'), retryBaseS: 0 }
    paths = { modulesStateFile: join(root, 'modules-state.json'), catalogIndexFile: join(root, 'catalog-index.json') }
    const lic = { spdx: 'Apache-2.0', restrictions: 'none' }
    const sarif = { sarif: { path: '/out/result.sarif', version: '2.1.0' } }
    const base = { type: 'scanner', license: lic, requires: { modules: [], feeds: [] }, conflicts: [], image: `ghcr.io/exemple/x@${DIGEST}` }
    await writeFile(paths.catalogIndexFile, JSON.stringify({
      schema: 1, version: 12, generated_at: '2026-11-24T00:00:00Z', packs: [],
      modules: [
        { ...base, id: 'syft', name: 'Syft', version: '1.0.0', categories: ['sbom'], outputs: { cyclonedx: { path: '/out/sbom.cdx.json', version: '1.6' } }, scan: { inputs: ['repo', 'archive'], command: ['x'], timeout_s: 900 } },
        { ...base, id: 'grype', name: 'Grype', version: '1.0.0', categories: ['sca', 'sbom'], outputs: sarif, scan: { inputs: ['repo', 'archive', 'sbom'], command: ['x'], sbom_command: ['y'], prefers_sbom: true, timeout_s: 1200 } },
        { ...base, id: 'trivy', name: 'Trivy', version: '1.0.0', categories: ['sca'], outputs: sarif, scan: { inputs: ['repo', 'archive'], command: ['x'], timeout_s: 600 } },
        { ...base, id: 'hadolint', name: 'hadolint', version: '1.0.0', categories: ['lint'], outputs: sarif, scan: { inputs: ['repo', 'archive'], command: ['x'], timeout_s: 60, applies_to: { detect: ['containers'] } } },
      ],
    }))
    await writeFile(paths.modulesStateFile, JSON.stringify({
      version: 1, updated_at: '2026-11-24T08:00:00Z', operations: [],
      modules: ['syft', 'grype', 'trivy', 'hadolint'].map(id => ({ id, version: '1.0.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-24T08:00:00Z', options: {}, testbed: null, route: null, last_error: null })),
    }))
    await writeFile(cfg.runnerStateFile, JSON.stringify({ slots: 4, busy: 0, updated_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') }))
    complet = (await db.pool.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'complet'`)).rows[0]!.id
    await db.pool.query(`UPDATE profiles SET categories = ARRAY['sbom', 'sca', 'lint'] WHERE id = $1`, [complet])
    gate = (await db.pool.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
  })

  afterAll(async () => {
    delete process.env.SCANORIA_RESULT_CACHE
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  beforeEach(async () => {
    await db.pool.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('queued', 'dispatched', 'running', 'ingesting')`)
    ingested.length = 0
    finalized.length = 0
  })

  it('order : graphe SBOM, durées mesurées du projet, tâche avec after et cache ; rejeu G11 identique', async () => {
    const p = await newProject()
    // Historique : trivy long sur ce projet, hadolint court ; grype jamais mesuré ici.
    const old = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
    await db.pool.query(`UPDATE scans SET status = 'done' WHERE id = $1`, [old.scanId])
    for (const [id, ms] of [['trivy', 400_000], ['hadolint', 1_000], ['syft', 30_000]] as const) {
      await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status, duration_ms, finished_at) VALUES ($1, $2, '1.0.0', 'ok', $3, now())`, [old.scanId, id, ms])
    }
    const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'manual' })
    const jobId = await dispatched(s.scanId)
    const plan = parsePlan((await db.pool.query('SELECT plan FROM scans WHERE id = $1', [s.scanId])).rows[0].plan)!
    // trivy (400 s) d'abord ; puis syft (30 s + grype 60 s par défaut) ; grype après syft ; hadolint en dernier.
    expect(plan.modules.map(m => m.id)).toEqual(['trivy', 'syft', 'grype', 'hadolint'])
    expect(plan.modules.find(m => m.id === 'grype')).toMatchObject({ after: ['syft'], expected_ms: 60_000 })
    expect(plan.modules.find(m => m.id === 'trivy')).toMatchObject({ after: [], expected_ms: 400_000 })
    const job = await takeJob(jobId)
    expect(job.cache).toBe(true)
    expect(job.modules.map(m => [m.id, m.after])).toEqual([['trivy', undefined], ['syft', undefined], ['grype', ['syft']], ['hadolint', undefined]])

    // Rejeu : même plan, même ordre, même graphe (G11).
    await db.pool.query(`UPDATE scans SET status = 'done' WHERE id = $1`, [s.scanId])
    const r = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'replay', replayOf: s.scanId })
    const rj = await takeJob(await dispatched(r.scanId))
    expect(rj.modules.map(m => [m.id, m.after])).toEqual(job.modules.map(m => [m.id, m.after]))
    expect(parsePlan((await db.pool.query('SELECT plan FROM scans WHERE id = $1', [r.scanId])).rows[0].plan)!.modules).toEqual(plan.modules)
  })

  it('cache : sortie rangée, puis reprise ingérée comme neuve, avec reused_from et compteur', async () => {
    const p = await newProject()
    const a = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'manual' })
    await runJob(await dispatched(a.scanId), { trivy: { cache_key: key('1') }, hadolint: { status: 'not-applicable' }, grype: { sbom_fallback: true, input: 'src' } })
    await worker().collect()
    const row = (await db.pool.query('SELECT * FROM result_cache WHERE cache_key = $1', [key('1')])).rows[0]
    expect(row).toMatchObject({ module_id: 'trivy', image_digest: DIGEST, source_scan: a.scanId, results_count: 2, duration_ms: 5000, hits: 0 })
    const meta = JSON.parse(await readFile(join(cacheDir, key('1'), 'meta.json'), 'utf8'))
    expect(meta).toEqual({ v: 1, key: key('1'), module_id: 'trivy', image_digest: DIGEST, outputs: { sarif: 'sarif.json' } })
    expect(await readFile(join(cacheDir, key('1'), 'sarif.json'), 'utf8')).toBe(JSON.stringify({ tool: 'trivy', reused: false }))
    expect(Number(row.size_bytes)).toBeGreaterThan(0)

    // V6 : not-applicable enregistré, jamais un échec : l'analyse reste complète ; couverture notée.
    const mods = (await db.pool.query('SELECT module_id, status, error_class FROM scan_modules WHERE scan_id = $1 ORDER BY module_id', [a.scanId])).rows
    expect(mods.find(m => m.module_id === 'hadolint')).toEqual({ module_id: 'hadolint', status: 'not-applicable', error_class: null })
    expect(finalized).toContainEqual([a.scanId, true])
    const cov = (await db.pool.query('SELECT coverage FROM scans WHERE id = $1', [a.scanId])).rows[0].coverage
    expect(cov.gaps).toEqual(expect.arrayContaining([
      { kind: 'not-applicable', code: 'not-applicable', module: 'hadolint', reason: 'no-matching-files' },
      { kind: 'sbom-fallback', module: 'grype' },
    ]))
    // V6 : détection rangée par arbre, clés invalides écartées.
    expect((await db.pool.query('SELECT detected FROM content_detection WHERE tree_sha = $1', [TREE])).rows[0].detected)
      .toEqual({ v: 1, keys: { python: 3, containers: 1 }, files: 12 })

    // Deuxième analyse : le runner a repris la sortie ; elle est ingérée par le même chemin qu'une neuve.
    const b = await enqueueScan(db.pool, { projectId: p, ref: 'v1', commit: COMMIT, trigger: 'release' })
    await runJob(await dispatched(b.scanId), { trivy: { reused_from: key('1') } })
    await worker().collect()
    const fresh = ingested.find(i => i.scanId === a.scanId && i.moduleId === 'trivy')!
    const reused = ingested.find(i => i.scanId === b.scanId && i.moduleId === 'trivy')!
    expect(reused.outputs).toEqual(fresh.outputs)
    const tm = (await db.pool.query(`SELECT status, reused_from, duration_ms FROM scan_modules WHERE scan_id = $1 AND module_id = 'trivy'`, [b.scanId])).rows[0]
    expect(tm).toEqual({ status: 'ok', reused_from: key('1'), duration_ms: null })
    expect((await db.pool.query('SELECT hits, last_hit_at FROM result_cache WHERE cache_key = $1', [key('1')])).rows[0]).toMatchObject({ hits: 1, last_hit_at: expect.any(Date) })
    // Page de l'analyse : « réutilisé depuis l'analyse n° 1 ».
    const detail = await getScan(db.pool, b.scanId)
    expect(detail!.modules.find((m: { module_id: string }) => m.module_id === 'trivy')).toMatchObject({ reused: true, reused_from_scan: a.scanId, reused_from_number: 1 })
    // Une sortie réutilisée n'est pas rangée une seconde fois.
    expect((await db.pool.query('SELECT count(*)::int AS n FROM result_cache')).rows[0].n).toBe(1)
  })

  it('cache : entrée disparue entre-temps → reused_from NULL, la sortie reste ingérée', async () => {
    const p = await newProject()
    const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'manual' })
    await runJob(await dispatched(s.scanId), { trivy: { reused_from: key('9') } })
    await worker().collect()
    expect((await db.pool.query(`SELECT status, reused_from FROM scan_modules WHERE scan_id = $1 AND module_id = 'trivy'`, [s.scanId])).rows[0]).toEqual({ status: 'ok', reused_from: null })
    expect(ingested.some(i => i.scanId === s.scanId && i.moduleId === 'trivy')).toBe(true)
  })

  it('cache : une analyse d’essai (F13) ne lit ni n’écrit le cache', async () => {
    const p = await newProject()
    const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'manual' })
    const trial = (await db.pool.query<{ id: string }>(
      `INSERT INTO module_trials (module_id, from_version, to_version, to_digest) VALUES ('trivy', '1.0.0', '1.1.0', $1) RETURNING id`, [DIGEST])).rows[0]!.id
    await db.pool.query(`UPDATE scans SET trigger = 'trial', trial_id = $2 WHERE id = $1`, [s.scanId, trial])
    const jobId = await dispatched(s.scanId)
    const job = JSON.parse(await readFile(join(cfg.scansDir, 'jobs', 'incoming', `${jobId}.json`), 'utf8')) as ScanJob
    expect(job.cache).toBe(false)
    await runJob(jobId, { trivy: { cache_key: key('2') } })
    await worker().collect()
    expect((await db.pool.query('SELECT count(*)::int AS n FROM result_cache WHERE cache_key = $1', [key('2')])).rows[0].n).toBe(0)
    await db.pool.query(`UPDATE module_trials SET status = 'done' WHERE id = $1`, [trial])
  })

  it('cache : clé invalide ou sortie illisible → rien n’est rangé, l’analyse n’échoue pas', async () => {
    const p = await newProject()
    const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'manual' })
    const jobId = await dispatched(s.scanId)
    await runJob(jobId, { trivy: { cache_key: key('3') }, syft: { cache_key: key('4') } })
    await rm(join(cfg.scansDir, 'results', jobId, 'syft', 'sbom.cdx.json'))
    // Sortie de syft supprimée après l'ingestion simulée : la lecture échoue au rangement.
    const orig = integrations.ingestModuleOutputs
    integrations.ingestModuleOutputs = async (_db, args) => (args.moduleId === 'syft' ? { count: 0, newCount: 0, errors: [] } : orig(_db, args))
    try {
      await worker().collect()
    }
    finally {
      integrations.ingestModuleOutputs = orig
    }
    const keys = (await db.pool.query<{ cache_key: string }>('SELECT cache_key FROM result_cache')).rows.map(r => r.cache_key)
    expect(keys).toContain(key('3'))
    expect(keys).not.toContain(key('4'))
    expect((await db.pool.query('SELECT status FROM scans WHERE id = $1', [s.scanId])).rows[0].status).toBe('done')
  })

  it('cache : éviction des images retirées, LRU au-delà de la taille, orphelins', async () => {
    const p = await newProject()
    const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
    await db.pool.query('DELETE FROM result_cache')
    const add = async (k: string, digest: string, size: number, lastHit: string) => {
      await mkdir(join(cacheDir, k), { recursive: true })
      await writeFile(join(cacheDir, k, 'meta.json'), '{}')
      await db.pool.query(
        `INSERT INTO result_cache (cache_key, module_id, image_digest, source_scan, results_count, size_bytes, created_at, last_hit_at)
         VALUES ($1, 'trivy', $2, $3, 0, $4, now() - interval '10 days', now() - $5::interval)`, [k, digest, s.scanId, size, lastHit])
    }
    await add(key('5'), DIGEST, 10 * 1024 * 1024, '1 hour')
    await add(key('6'), DIGEST, 10 * 1024 * 1024, '2 hours')
    await add(key('7'), OLD_DIGEST, 1024, '1 minute')
    await mkdir(join(cacheDir, key('8')), { recursive: true })
    await mkdir(join(cacheDir, '.tmp-x'), { recursive: true })
    await mkdir(join(cacheDir, 'autre'), { recursive: true })
    // Taille maximale par défaut (2 Gio) : seule l'image retirée part.
    expect(await purgeCache(db.pool, paths, cacheDir)).toBe(1)
    // 16 Mio au plus : la moins récemment utilisée part aussi.
    const r = await purgeResultCache(db.pool, { cacheDir, maxBytes: 16 * 1024 * 1024, liveDigests: null })
    expect(r.removed).toBe(1)
    expect((await db.pool.query<{ cache_key: string }>('SELECT cache_key FROM result_cache')).rows.map(x => x.cache_key)).toEqual([key('5')])
    expect((await readdir(cacheDir)).sort()).toEqual([key('5'), 'autre'].sort())
    // Version figée par un projet (G6) : son empreinte reste vivante.
    await add(key('7'), OLD_DIGEST, 1024, '1 minute')
    await db.pool.query(`INSERT INTO project_module_pins (project_id, module_id, version, image_digest, reason) VALUES ($1, 'trivy', '0.9.0', $2, 'audit')`, [p, OLD_DIGEST])
    expect(await purgeCache(db.pool, paths, cacheDir)).toBe(0)
  })
})
