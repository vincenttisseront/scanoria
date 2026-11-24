// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// scanoria-worker contre un vrai PostgreSQL 16 et un faux runner (répertoires
// temporaires, contrat 8) : mise en file (contrat 4), ordonnancement (G17),
// plan figé et rejeu (G11), relances (G12), délai, annulation, redémarrage,
// enchaînement ingestion → finalisation → verdict → IA (contrats 5, 6, 7), API.

import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, open, readFile, readdir, rm, symlink, utimes, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, defineEventHandler, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { VerdictDetails } from '#shared/analysis'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadWorkerConfig, type WorkerConfig } from '../../server/scans/config'
import type { EnqueueScanError } from '../../server/scans/enqueue'
import { enqueueScan } from '../../server/scans/enqueue'
import { defaultIntegrations, pendingGate, type Integrations } from '../../server/scans/integrations'
import { ScanWorker, cancelScan } from '../../server/scans/worker'
import { WorkerService } from '../../server/scans/service'
import { getScan, listScans } from '../../server/scans/api'
import type { ScanJob } from '../../server/scans/contract'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'

const COMMIT = 'c'.repeat(40)
const DIGEST = `sha256:${'d'.repeat(64)}`

describe.skipIf(!DATABASE_URL)('file d’analyses (PostgreSQL réel, faux runner)', () => {
  let db: TestDatabase
  let root: string
  let cfg: WorkerConfig
  let paths: { modulesStateFile: string, catalogIndexFile: string }
  let rapide: string
  let complet: string
  let gate: string
  const logs: string[] = []

  // Appels faits aux autres chantiers (bouchons de test des contrats 2, 5, 6, 7).
  const seen = { ingest: [] as { scanId: string, moduleId: string, resultDir: string, outputs: Record<string, string> }[], finalize: [] as [string, boolean][], ai: [] as unknown[], schedules: 0 }
  let secret: { kind: string, value: string, username?: string } | Error = new Error('none')
  const integrations: Integrations = {
    decryptSecret: async () => {
      if (secret instanceof Error) throw secret
      return { ...secret, username: secret.username ?? null }
    },
    ingestModuleOutputs: async (_db, args) => {
      seen.ingest.push(args)
      if (args.moduleId === 'broken-ingest') throw new Error('boom')
      return { count: 3, newCount: 1, errors: args.moduleId === 'trivy' ? [{ code: 'truncated' }] : args.moduleId === 'bad-output' ? [{ code: 'invalid-document' }] : [] }
    },
    finalizeScanFindings: async (_db, scanId, { complete }) => {
      seen.finalize.push([scanId, complete])
    },
    evaluateGate: async (pool, scanId) => {
      const base = await pendingGate(pool, scanId)
      const r = await pool.query<{ n: number }>(`SELECT count(*)::int AS n FROM scan_modules WHERE scan_id = $1 AND status <> 'ok'`, [scanId])
      const m = await pool.query<{ n: number }>('SELECT count(*)::int AS n FROM scan_modules WHERE scan_id = $1', [scanId])
      return { ...base, verdict: (r.rows[0]!.n === 0 && m.rows[0]!.n > 0 ? 'passed' : 'inconclusive') as VerdictDetails['verdict'] }
    },
    enqueueAiTask: async (_db, req) => {
      seen.ai.push(req)
      return null
    },
    runProjectSchedules: async (_db, _now, enqueue) => {
      seen.schedules++
      expect(enqueue).toBe(enqueueScan)
    },
  }

  const worker = (over: Partial<WorkerConfig> = {}) => new ScanWorker(db.pool, { ...cfg, ...over }, paths, integrations, m => logs.push(m))

  async function setRunner(slots: number, busy = 0, updatedAt = new Date()) {
    await writeFile(cfg.runnerStateFile, JSON.stringify({ slots, busy, updated_at: updatedAt.toISOString().replace(/\.\d+Z$/, 'Z') }))
  }

  async function setInstalled(mods: { id: string, version: string, status?: string, enabled?: boolean, type?: string }[]) {
    await writeFile(paths.modulesStateFile, JSON.stringify({
      version: 1, updated_at: '2026-11-24T08:00:00Z', operations: [],
      modules: mods.map(m => ({ type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-24T08:00:00Z', options: {}, testbed: null, route: null, last_error: null, ...m })),
    }))
  }

  async function newProject(extra: Record<string, unknown> = {}): Promise<string> {
    const slug = `p-${randomUUID().slice(0, 8)}`
    const cols = { slug, name: `Projet ${slug}`, source_kind: 'git', repo_url: `https://forge.exemple.test/exemple/${slug}.git`, default_branch: 'main', profile_id: rapide, gate_id: gate, ...extra }
    const keys = Object.keys(cols)
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (${keys.join(', ')}) VALUES (${keys.map((_, i) => `$${i + 1}`).join(', ')}) RETURNING id`, Object.values(cols))
    return r.rows[0]!.id
  }

  const scanRow = async (id: string) => (await db.pool.query('SELECT * FROM scans WHERE id = $1', [id])).rows[0]
  const moduleRows = async (id: string) => (await db.pool.query('SELECT * FROM scan_modules WHERE scan_id = $1 ORDER BY module_id', [id])).rows
  const incoming = async () => (await readdir(join(cfg.scansDir, 'jobs', 'incoming'))).sort()
  async function takeJob(jobId: string): Promise<ScanJob> {
    const path = join(cfg.scansDir, 'jobs', 'incoming', `${jobId}.json`)
    const job = JSON.parse(await readFile(path, 'utf8')) as ScanJob
    await rm(path)
    return job
  }

  /** Faux runner : prend la tâche et publie un résultat conforme à scan-result. */
  async function runJob(jobId: string, opts: {
    status?: 'ok' | 'error'
    error?: { code: string, class: 'infra' | 'tool' | 'input', message: string } | null
    modules?: Record<string, { status?: string, error?: { code: string, class: 'infra' | 'tool' | 'input', message: string } }>
    scanId?: string
  } = {}): Promise<ScanJob> {
    const job = await takeJob(jobId)
    const dir = join(cfg.scansDir, 'results', jobId)
    await mkdir(dir, { recursive: true })
    const modules = opts.status === 'error' && !opts.modules
      ? []
      : job.modules.map((m) => {
          const o = opts.modules?.[m.id] ?? {}
          return {
            id: m.id, version: m.version, status: o.status ?? 'ok', error: o.error ?? null, image_digest: DIGEST,
            feeds: [{ id: 'trivy-db', version: '2', updated_at: '2026-11-24T00:00:00Z' }],
            started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:00:05Z', exit_code: 0,
            outputs: (o.status ?? 'ok') === 'ok' ? { sarif: `${m.id}/result.sarif` } : {}, log: `${m.id}/module.log`,
            stats: { duration_ms: 5000, peak_memory_mb: 100, cpu_ms: 2000 },
          }
        })
    for (const m of job.modules) {
      await mkdir(join(dir, m.id), { recursive: true })
      await writeFile(join(dir, m.id, 'module.log'), `log ${m.id}\n`)
    }
    await writeFile(join(dir, 'result.json'), JSON.stringify({
      schema: 1, id: job.id, scan_id: opts.scanId ?? job.scan_id, status: opts.status ?? 'ok', error: opts.error ?? null,
      started_at: '2026-11-24T10:00:00Z', finished_at: '2026-11-24T10:01:00Z',
      source: { kind: job.source.kind, commit: job.source.kind === 'git' ? COMMIT : null, history: 'shallow', files: 12, bytes: 3456, skipped: [{ path: 'big.bin', reason: 'size' }] },
      modules,
    }))
    return job
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-worker-'))
    for (const d of ['scans/jobs/tmp', 'scans/jobs/incoming', 'scans/results', 'logs']) await mkdir(join(root, d), { recursive: true })
    cfg = {
      ...loadWorkerConfig({}),
      scansDir: join(root, 'scans'),
      runnerStateFile: join(root, 'runner.json'),
      scanLogsDir: join(root, 'logs'),
      heartbeatFile: join(root, 'console', 'worker.json'),
      retryBaseS: 0,
      resultMarginS: 60,
    }
    paths = { modulesStateFile: join(root, 'modules-state.json'), catalogIndexFile: join(root, 'catalog-index.json') }
    const scan = (timeout: number, history?: string) => ({ inputs: ['repo', 'archive'], command: ['x'], timeout_s: timeout, network: 'none', ...(history ? { history } : {}) })
    await writeFile(paths.catalogIndexFile, JSON.stringify({
      schema: 1, version: 7, generated_at: '2026-11-24T00:00:00Z', packs: [],
      modules: [
        { id: 'gitleaks', name: 'gitleaks', type: 'scanner', version: '8.30.1', categories: ['secrets'], license: { spdx: 'MIT', restrictions: 'none' }, image: `ghcr.io/exemple/gitleaks@${DIGEST}`, requires: { modules: [], feeds: [] }, conflicts: [], outputs: { sarif: { path: '/out/result.sarif', version: '2.1.0' } }, scan: scan(900, 'full'), options: { type: 'object', properties: { history: { type: 'boolean', default: true } } } },
        { id: 'trivy', name: 'Trivy', type: 'scanner', version: '0.76.2', categories: ['sca', 'secrets'], license: { spdx: 'Apache-2.0', restrictions: 'none' }, image: `ghcr.io/exemple/trivy@${DIGEST}`, requires: { modules: [], feeds: ['trivy-db'] }, conflicts: [], outputs: { sarif: { path: '/out/result.sarif', version: '2.1.0' } }, scan: scan(600) },
        { id: 'broken-ingest', name: 'x', type: 'scanner', version: '1.0.0', categories: ['lint'], license: { spdx: 'MIT', restrictions: 'none' }, requires: { modules: [], feeds: [] }, conflicts: [], outputs: { sarif: { path: '/out/r.sarif', version: '2.1.0' } }, scan: scan(60) },
        { id: 'bad-output', name: 'x', type: 'scanner', version: '1.0.0', categories: ['lint'], license: { spdx: 'MIT', restrictions: 'none' }, requires: { modules: [], feeds: [] }, conflicts: [], outputs: { sarif: { path: '/out/r.sarif', version: '2.1.0' } }, scan: scan(60) },
        { id: 'trivy-db', name: 'trivy-db', type: 'feed', version: '2', categories: [], license: { spdx: 'Apache-2.0', restrictions: 'none' }, requires: { modules: [], feeds: [] }, conflicts: [] },
      ],
    }))
    const p = await db.pool.query<{ id: string, slug: string }>('SELECT id, slug FROM profiles')
    rapide = p.rows.find(r => r.slug === 'rapide')!.id
    complet = p.rows.find(r => r.slug === 'complet')!.id
    gate = (await db.pool.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url }))
  })

  afterAll(async () => {
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  beforeEach(async () => {
    // Chaque test part d'une file vide (les analyses des tests précédents sont closes).
    await db.pool.query(`UPDATE scans SET status = 'cancelled' WHERE status IN ('queued', 'dispatched', 'running', 'ingesting')`)
    for (const f of await incoming()) await rm(join(cfg.scansDir, 'jobs', 'incoming', f))
    await setInstalled([{ id: 'gitleaks', version: '8.30.1' }, { id: 'trivy', version: '0.76.2' }, { id: 'trivy-db', version: '2', type: 'feed' }])
    await setRunner(4)
    seen.ingest.length = 0
    seen.finalize.length = 0
    seen.ai.length = 0
    secret = new Error('none')
  })

  describe('enqueueScan (contrat 4)', () => {
    it('numéro par projet, priorité du déclencheur, fusion des doublons en file', async () => {
      const p = await newProject()
      const a = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'schedule' })
      const b = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'release' })
      expect(a).toMatchObject({ number: 1, merged: false })
      expect(b).toEqual({ scanId: a.scanId, number: 1, merged: true })
      expect((await scanRow(a.scanId)).priority).toBe(90)
      const c = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: COMMIT, trigger: 'api' })
      const d = await enqueueScan(db.pool, { projectId: p, ref: 'other', commit: COMMIT, trigger: 'api' })
      expect(c.number).toBe(2)
      expect(d).toMatchObject({ scanId: c.scanId, merged: true })
      const e = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual', profileSlug: 'complet' })
      expect(e).toMatchObject({ number: 3, merged: false })
      expect((await scanRow(e.scanId)).profile_id).toBe(complet)
      // Numérotation sans trou ni doublon sous concurrence.
      const many = await Promise.all(Array.from({ length: 8 }, (_, i) => enqueueScan(db.pool, { projectId: p, ref: `b${i}`, trigger: 'manual' })))
      expect(many.map(x => x.number).sort((x, y) => x - y)).toEqual([4, 5, 6, 7, 8, 9, 10, 11])
    })

    it('refus : projet inconnu ou archivé, ref hostile, profil inconnu, rejeu sans plan, archive sans téléversement', async () => {
      const p = await newProject()
      const code = async (fn: () => Promise<unknown>) => fn().then(() => 'ok', (e: EnqueueScanError) => e.code)
      expect(await code(() => enqueueScan(db.pool, { projectId: randomUUID(), ref: 'main', trigger: 'manual' }))).toBe('E_SCAN_PROJECT_NOT_FOUND')
      expect(await code(() => enqueueScan(db.pool, { projectId: 'x', ref: 'main', trigger: 'manual' }))).toBe('E_SCAN_PROJECT_NOT_FOUND')
      for (const ref of ['--upload-pack=id', 'a..b', 'a b', '']) {
        expect(await code(() => enqueueScan(db.pool, { projectId: p, ref, trigger: 'manual' }))).toBe('E_SCAN_REF')
      }
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', commit: 'abc', trigger: 'manual' }))).toBe('E_SCAN_REF')
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual', profileSlug: 'inconnu' }))).toBe('E_SCAN_PROFILE')
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual', profileSlug: 'Bad' }))).toBe('E_SCAN_PROFILE')
      const s = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'replay', replayOf: s.scanId }))).toBe('E_SCAN_REPLAY')
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'replay' }))).toBe('E_SCAN_REPLAY')
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual', replayOf: s.scanId }))).toBe('E_SCAN_REPLAY')
      const arch = await newProject({ source_kind: 'archive', repo_url: null })
      expect(await code(() => enqueueScan(db.pool, { projectId: arch, ref: 'x', trigger: 'manual' }))).toBe('E_SCAN_SOURCE')
      await db.pool.query('UPDATE projects SET archived_at = now() WHERE id = $1', [p])
      expect(await code(() => enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' }))).toBe('E_SCAN_PROJECT_ARCHIVED')
    })
  })

  describe('ordonnancement (G17)', () => {
    it('priorité effective puis ancienneté ; anti-famine ; quota par projet ; un seul dépôt par analyse', async () => {
      const [p1, p2, p3] = [await newProject(), await newProject(), await newProject()]
      const sched = await enqueueScan(db.pool, { projectId: p1, ref: 'main', trigger: 'schedule' })
      const manual = await enqueueScan(db.pool, { projectId: p2, ref: 'main', trigger: 'manual' })
      const rel = await enqueueScan(db.pool, { projectId: p3, ref: 'v1', trigger: 'release' })
      // La planifiée attend depuis longtemps : elle passe devant la manuelle récente, jamais devant la release.
      await db.pool.query(`UPDATE scans SET queued_at = now() - interval '4 hours' WHERE id = $1`, [sched.scanId])
      const w = worker()
      const order: string[] = []
      for (let i = 0; i < 3; i++) {
        expect(await w.dispatchOne()).toBe('dispatched')
        const r = await db.pool.query<{ id: string }>(`SELECT id FROM scans WHERE status = 'dispatched' AND id <> ALL($1::uuid[])`, [order])
        order.push(r.rows[0]!.id)
      }
      expect(order).toEqual([rel.scanId, sched.scanId, manual.scanId])

      const p4 = await newProject()
      const q = await Promise.all([0, 1, 2].map(i => enqueueScan(db.pool, { projectId: p4, ref: `b${i}`, trigger: 'release' })))
      await setRunner(20)
      expect(await worker().dispatch()).toBe(2)
      const states = await Promise.all(q.map(async x => (await scanRow(x.scanId)).status))
      expect(states.sort()).toEqual(['dispatched', 'dispatched', 'queued'])
    })

    it('capacité : runner absent, muet, plein ; deux workers ne prennent jamais la même analyse', async () => {
      const p = [await newProject(), await newProject(), await newProject(), await newProject()]
      for (const id of p) await enqueueScan(db.pool, { projectId: id, ref: 'main', trigger: 'manual' })
      await rm(cfg.runnerStateFile)
      expect(await worker().dispatch()).toBe(0)
      await setRunner(4, 0, new Date(Date.now() - 3600_000))
      expect(await worker().dispatch()).toBe(0)
      await setRunner(4, 4)
      expect(await worker().dispatch()).toBe(0)
      await writeFile(cfg.runnerStateFile, '{"slots": "many"}')
      expect(await worker().freeSlots()).toBe(0)
      await setRunner(8, 1)
      const results = await Promise.all([worker().dispatch(), worker().dispatch(), worker().dispatch()])
      expect(results.reduce((a, b) => a + b, 0)).toBe(4)
      const files = await incoming()
      expect(files).toHaveLength(4)
      const scans = await Promise.all(files.map(async f => JSON.parse(await readFile(join(cfg.scansDir, 'jobs', 'incoming', f), 'utf8')).scan_id))
      expect(new Set(scans).size).toBe(4)
      expect(await worker().freeSlots()).toBe(4)
    })
  })

  describe('déroulement d’une analyse', () => {
    it('succès : tâche 0600 sans secret, plan figé, ingestion, couverture, journaux, verdict, IA', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      expect(await w.dispatch()).toBe(1)
      const row = await scanRow(scanId)
      expect(row.status).toBe('dispatched')
      const jobPath = join(cfg.scansDir, 'jobs', 'incoming', `${row.job_id}.json`)
      // Mode et contenu lus sur le même descripteur.
      const fh = await open(jobPath, 'r')
      let job: ScanJob
      try {
        expect((await fh.stat()).mode & 0o777).toBe(0o600)
        job = JSON.parse(await fh.readFile('utf8')) as ScanJob
      }
      finally {
        await fh.close()
      }
      expect(await readdir(join(cfg.scansDir, 'jobs', 'tmp'))).toEqual([])
      expect(job.source).toEqual({ kind: 'git', url: expect.stringMatching(/^https:\/\/forge\.exemple\.test\//), ref: 'main', history: 'full', credential: null })
      expect(job.modules).toEqual([{ id: 'gitleaks', version: '8.30.1', options: { history: true } }, { id: 'trivy', version: '0.76.2', options: {} }])
      expect(row.plan.modules.map((m: { id: string }) => m.id)).toEqual(['gitleaks', 'trivy'])
      expect(row.plan.gate.slug).toBe('defaut')
      // « rapide » : secrets, sca, lint, ci ; lint et ci sans module → trous de couverture.
      expect(row.coverage.gaps).toEqual([
        { kind: 'profile-category', category: 'lint', module: null, reason: 'no-module' },
        { kind: 'profile-category', category: 'ci', module: null, reason: 'no-module' },
      ])
      expect((await moduleRows(scanId)).map(m => [m.module_id, m.status])).toEqual([['gitleaks', 'pending'], ['trivy', 'pending']])

      // Le runner prend la tâche : l'analyse passe « running ».
      const taken = await takeJob(row.job_id)
      await w.collect()
      expect((await scanRow(scanId)).status).toBe('running')
      await writeFile(join(cfg.scansDir, 'jobs', 'incoming', `${row.job_id}.json`), JSON.stringify(taken), { mode: 0o600 })
      await runJob(row.job_id)
      await w.tick()
      const done = await scanRow(scanId)
      expect(done).toMatchObject({ status: 'done', verdict: 'passed', commit_sha: COMMIT, error: null })
      expect(done.plan.source.commit).toBe(COMMIT)
      expect(done.verdict_details.verdict).toBe('passed')
      expect(done.coverage.source).toEqual({ files: 12, bytes: 3456, history: 'shallow', skipped: [{ path: 'big.bin', reason: 'size' }] })
      expect(done.coverage.gaps).toHaveLength(2)
      const mods = await moduleRows(scanId)
      expect(mods.map(m => [m.module_id, m.status, m.results_count, m.duration_ms, m.image_digest])).toEqual([
        ['gitleaks', 'ok', 3, 5000, DIGEST], ['trivy', 'ok', 3, 5000, DIGEST],
      ])
      expect(mods[0].log_path).toBe(`${scanId}/gitleaks.log`)
      const log = join(cfg.scanLogsDir, scanId, 'gitleaks.log')
      const lh = await open(log, 'r')
      try {
        expect(await lh.readFile('utf8')).toBe('log gitleaks\n')
        expect((await lh.stat()).mode & 0o777).toBe(0o600)
      }
      finally {
        await lh.close()
      }
      expect(seen.ingest.map(i => [i.scanId, i.moduleId, i.outputs])).toEqual([
        [scanId, 'gitleaks', { sarif: 'gitleaks/result.sarif' }], [scanId, 'trivy', { sarif: 'trivy/result.sarif' }],
      ])
      expect(seen.ingest[0]!.resultDir).toBe(join(cfg.scansDir, 'results', row.job_id))
      expect(seen.finalize).toEqual([[scanId, true]])
      expect(seen.ai).toEqual([{ kind: 'explain-verdict', subjectType: 'scan', subjectId: scanId, projectId: p, priority: 10 }])
      // Une seconde passe ne retraite rien.
      await w.tick()
      expect(seen.finalize).toHaveLength(1)
      expect(logs.some(l => l.includes('ingestion error'))).toBe(true)
    })

    it('erreur infra : relancée avec recul, puis succès (G12)', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker({ retryBaseS: 3600 })
      await w.dispatch()
      const first = (await scanRow(scanId)).job_id
      await runJob(first, { modules: { trivy: { status: 'oom', error: { code: 'E_OOM', class: 'infra', message: 'out of memory' } } } })
      await w.tick()
      let row = await scanRow(scanId)
      expect(row).toMatchObject({ status: 'queued', attempt: 2, job_id: null })
      expect(row.error).toMatchObject({ code: 'E_OOM', class: 'infra' })
      expect(Date.parse(row.error.retry_at)).toBeGreaterThan(Date.now() + 3000_000)
      expect((await moduleRows(scanId)).map(m => m.status)).toEqual(['pending', 'pending'])
      expect(seen.finalize).toEqual([])
      // Recul pas écoulé : rien n'est redéposé.
      expect(await w.dispatch()).toBe(0)
      await db.pool.query(`UPDATE scans SET error = error || '{"retry_at": "2000-01-01T00:00:00Z"}' WHERE id = $1`, [scanId])
      expect(await w.dispatch()).toBe(1)
      row = await scanRow(scanId)
      expect(row.job_id).not.toBe(first)
      await runJob(row.job_id)
      await w.tick()
      row = await scanRow(scanId)
      expect(row).toMatchObject({ status: 'done', verdict: 'passed', attempt: 2, error: null })
      expect((await moduleRows(scanId)).map(m => m.attempts)).toEqual([2, 2])
    })

    it('erreur infra répétée : au plus 2 relances, puis analyse en erreur et non concluante', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      expect(await w.dispatch()).toBe(1)
      for (let i = 0; i < 3; i++) {
        // Recul nul : la passe relève l'erreur et redépose aussitôt la relance.
        await runJob((await scanRow(scanId)).job_id, { status: 'error', error: { code: 'E_PODMAN', class: 'infra', message: 'podman failed' } })
        await w.tick()
      }
      const row = await scanRow(scanId)
      expect(row).toMatchObject({ status: 'error', verdict: 'inconclusive', attempt: 3 })
      expect(row.error).toEqual({ code: 'E_PODMAN', class: 'infra', message: 'podman failed' })
      expect((await moduleRows(scanId)).map(m => [m.status, m.error_class])).toEqual([['error', 'infra'], ['error', 'infra']])
      expect(seen.finalize).toEqual([[scanId, false]])
    })

    it('erreurs tool et input : jamais relancées ; ingestion en échec = sortie invalide', async () => {
      await setInstalled([{ id: 'gitleaks', version: '8.30.1' }, { id: 'trivy', version: '0.76.2' }, { id: 'broken-ingest', version: '1.0.0' }, { id: 'bad-output', version: '1.0.0' }])
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      await runJob((await scanRow(scanId)).job_id, { modules: { trivy: { status: 'invalid-output', error: { code: 'E_SARIF', class: 'tool', message: 'bad sarif' } } } })
      await w.tick()
      expect(await scanRow(scanId)).toMatchObject({ status: 'done', verdict: 'inconclusive', attempt: 1 })
      expect((await moduleRows(scanId)).map(m => [m.module_id, m.status, m.error_class])).toEqual([
        ['bad-output', 'invalid-output', 'tool'], ['broken-ingest', 'invalid-output', 'tool'], ['gitleaks', 'ok', null], ['trivy', 'invalid-output', 'tool'],
      ])
      expect(seen.finalize).toEqual([[scanId, false]])

      const p2 = await newProject()
      const s2 = await enqueueScan(db.pool, { projectId: p2, ref: 'main', trigger: 'manual' })
      await w.dispatch()
      await runJob((await scanRow(s2.scanId)).job_id, { status: 'error', error: { code: 'E_FETCH', class: 'input', message: 'repository unreachable' } })
      await w.tick()
      const r2 = await scanRow(s2.scanId)
      expect(r2).toMatchObject({ status: 'error', verdict: 'inconclusive', attempt: 1, error: { code: 'E_FETCH', class: 'input' } })
      expect((await moduleRows(s2.scanId)).every(m => m.status === 'error' && m.error_class === 'input')).toBe(true)
    })

    it('résultat invalide ou d’une autre analyse : erreur infra relancée ; tâche refusée reconnue par son id', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      let jobId = (await scanRow(scanId)).job_id
      await takeJob(jobId)
      await mkdir(join(cfg.scansDir, 'results', jobId), { recursive: true })
      await writeFile(join(cfg.scansDir, 'results', jobId, 'result.json'), '{"schema": 1}')
      await w.collect()
      expect(await scanRow(scanId)).toMatchObject({ status: 'queued', attempt: 2, error: { code: 'E_RESULT_INVALID' } })
      await w.dispatch()
      jobId = (await scanRow(scanId)).job_id
      await runJob(jobId, { scanId: randomUUID() })
      await w.collect()
      expect(await scanRow(scanId)).toMatchObject({ status: 'queued', attempt: 3 })
      await w.dispatch()
      jobId = (await scanRow(scanId)).job_id
      await runJob(jobId, { scanId: '00000000-0000-4000-8000-000000000000', status: 'error', error: { code: 'E_JOB_INVALID', class: 'input', message: 'job rejected' } })
      await w.collect()
      expect(await scanRow(scanId)).toMatchObject({ status: 'error', error: { code: 'E_JOB_INVALID' } })
    })

    it('délai dépassé sans résultat : tâche retirée, erreur infra E_RESULT_TIMEOUT relancée', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      const jobId = (await scanRow(scanId)).job_id
      await w.collect()
      expect((await scanRow(scanId)).status).toBe('dispatched')
      // plan : 900 + 600 s, marge 60 s.
      await db.pool.query(`UPDATE scans SET started_at = now() - interval '1561 seconds' WHERE id = $1`, [scanId])
      await w.collect()
      expect(await scanRow(scanId)).toMatchObject({ status: 'queued', attempt: 2, error: { code: 'E_RESULT_TIMEOUT', class: 'infra' } })
      expect(await incoming()).not.toContain(`${jobId}.json`)
    })

    it('redémarrage : un nouveau worker reprend une analyse déposée et une ingestion interrompue', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      await worker().dispatch()
      await runJob((await scanRow(scanId)).job_id)
      // Arrêt pendant l'ingestion : l'état « ingesting » reste en base.
      await db.pool.query(`UPDATE scans SET status = 'ingesting' WHERE id = $1`, [scanId])
      await worker().tick()
      expect(await scanRow(scanId)).toMatchObject({ status: 'done', verdict: 'passed', attempt: 1 })
    })

    it('secret de la source déchiffré au dernier moment ; échec → erreur input sans fuite', async () => {
      const cred = await db.pool.query<{ id: string }>(`INSERT INTO credentials (kind, secret_enc, hint) VALUES ('token', '\\x01', '…abcd') RETURNING id`)
      const p = await newProject({ credential_id: cred.rows[0]!.id })
      const token = `scn_${randomUUID().replace(/-/g, '')}abcdefgh`
      secret = { kind: 'token', value: token, username: 'ci' }
      const s1 = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      await worker().dispatch()
      const job = JSON.parse(await readFile(join(cfg.scansDir, 'jobs', 'incoming', `${(await scanRow(s1.scanId)).job_id}.json`), 'utf8')) as ScanJob
      expect(job.source).toMatchObject({ credential: { kind: 'token', token, username: 'ci' } })
      expect(JSON.stringify(await scanRow(s1.scanId))).not.toContain(token)
      expect(logs.join('\n')).not.toContain(token)

      secret = new Error('key missing')
      const p2 = await newProject({ credential_id: cred.rows[0]!.id })
      const s2 = await enqueueScan(db.pool, { projectId: p2, ref: 'main', trigger: 'manual' })
      expect(await worker().dispatchOne()).toBe('finished')
      expect(await scanRow(s2.scanId)).toMatchObject({ status: 'error', verdict: 'inconclusive', error: { code: 'E_SCAN_CREDENTIAL', class: 'input' } })

      secret = { kind: 'ssh-key', value: 'x' }
      const p3 = await newProject({ credential_id: cred.rows[0]!.id, repo_url: 'ssh://git@forge.exemple.test/a/b.git' })
      const s3 = await enqueueScan(db.pool, { projectId: p3, ref: 'main', trigger: 'manual' })
      expect(await worker().dispatchOne()).toBe('finished')
      expect(await scanRow(s3.scanId)).toMatchObject({ status: 'error', error: { code: 'E_SCAN_KNOWN_HOSTS' } })

      secret = { kind: 'token', value: 'contient des espaces' }
      const s4 = await enqueueScan(db.pool, { projectId: await newProject({ credential_id: cred.rows[0]!.id }), ref: 'main', trigger: 'manual' })
      expect(await worker().dispatchOne()).toBe('finished')
      const r4 = await scanRow(s4.scanId)
      expect(r4.error).toMatchObject({ code: 'E_SCAN_SOURCE', class: 'input' })
      expect(JSON.stringify(r4)).not.toContain('contient des espaces')
    })

    it('plan vide : analyse conclue sans runner, non concluante, trous signalés', async () => {
      await setInstalled([])
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      expect(await worker().dispatchOne()).toBe('finished')
      const row = await scanRow(scanId)
      expect(row).toMatchObject({ status: 'done', verdict: 'inconclusive', job_id: null })
      expect(row.coverage.gaps.map((g: { category: string }) => g.category)).toEqual(['secrets', 'sca', 'lint', 'ci'])
      expect(await incoming()).toEqual([])
    })
  })

  describe('relecture : robustesse et confinement', () => {
    it('le runner recopie le jeton dans son erreur et dans un journal : masqué avant stockage', async () => {
      const cred = await db.pool.query<{ id: string }>(`INSERT INTO credentials (kind, secret_enc, hint) VALUES ('token', '\\x01', '…abcd') RETURNING id`)
      const p = await newProject({ credential_id: cred.rows[0]!.id })
      const token = `scn_${randomUUID().replace(/-/g, '')}abcdefgh`
      secret = { kind: 'token', value: token, username: 'ci' }
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker({ maxInfraRetries: 0 })
      await w.dispatch()
      const jobId = (await scanRow(scanId)).job_id
      await runJob(jobId, { modules: { gitleaks: { status: 'error', error: { code: 'E_TOOL', class: 'tool', message: `fatal: unable to access 'https://ci:${token}@forge.exemple.test/a.git'` } } } })
      await writeFile(join(cfg.scansDir, 'results', jobId, 'gitleaks', 'module.log'), `Authorization: Bearer ${token}\nurl=https://${encodeURIComponent(token)}@forge.exemple.test\n`)
      await w.collect()
      const row = await scanRow(scanId)
      expect(row.status, JSON.stringify(row.error)).toBe('done')
      const log = await readFile(join(cfg.scanLogsDir, scanId, 'gitleaks.log'), 'utf8')
      expect(log).toContain('[masqué]')
      expect(log).not.toContain(token)
      expect(JSON.stringify(row)).not.toContain(token)

      // Erreur infra relancée : le message stocké pour la relance est masqué aussi.
      const s2 = await enqueueScan(db.pool, { projectId: p, ref: 'other', trigger: 'manual' })
      const w2 = worker()
      await w2.dispatch()
      await runJob((await scanRow(s2.scanId)).job_id, { status: 'error', error: { code: 'E_OOM', class: 'infra', message: `clone https://${token}@forge.exemple.test failed` } })
      await w2.collect()
      const r2 = await scanRow(s2.scanId)
      expect(r2.status).toBe('queued')
      expect(JSON.stringify(r2)).not.toContain(token)
    })

    it('journal par un lien de répertoire vers l’extérieur : jamais copié ; result.json sous un lien : refusé', async () => {
      const outside = await mkdtemp(join(tmpdir(), 'scanoria-outside-'))
      await writeFile(join(outside, 'secret.key'), 'contenu hors de results')
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      const jobId = (await scanRow(scanId)).job_id
      await runJob(jobId)
      const dir = join(cfg.scansDir, 'results', jobId)
      await symlink(outside, join(dir, 'escape'))
      const res = JSON.parse(await readFile(join(dir, 'result.json'), 'utf8'))
      res.modules[0].log = 'escape/secret.key'
      await writeFile(join(dir, 'result.json'), JSON.stringify(res))
      await w.collect()
      const mods = await moduleRows(scanId)
      expect(mods.find(m => m.module_id === res.modules[0].id).log_path).toBeNull()
      expect(JSON.stringify(await readdir(join(cfg.scanLogsDir, scanId)))).not.toContain('secret')

      // Répertoire de résultat entier remplacé par un lien.
      const s2 = await enqueueScan(db.pool, { projectId: p, ref: 'other', trigger: 'manual' })
      await w.dispatch()
      const job2 = (await scanRow(s2.scanId)).job_id
      await takeJob(job2)
      await writeFile(join(outside, 'result.json'), '{}')
      await symlink(outside, join(cfg.scansDir, 'results', job2))
      await w.collect()
      expect(await scanRow(s2.scanId)).toMatchObject({ status: 'queued', error: { code: 'E_RESULT_INVALID' } })
      await rm(outside, { recursive: true, force: true })
    })

    it('état des modules ou catalogue illisible : analyse laissée en file, rien de figé', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      await rm(paths.modulesStateFile)
      expect(await worker().dispatchOne()).toBe('deferred')
      let row = await scanRow(scanId)
      expect(row).toMatchObject({ status: 'queued', plan: null, attempt: 1, error: { code: 'E_MODULES_STATE', class: 'infra' } })
      expect(await moduleRows(scanId)).toEqual([])
      await setInstalled([{ id: 'gitleaks', version: '8.30.1' }])
      const catalog = await readFile(paths.catalogIndexFile, 'utf8')
      await writeFile(paths.catalogIndexFile, '{')
      await db.pool.query(`UPDATE scans SET error = NULL WHERE id = $1`, [scanId])
      expect(await worker().dispatchOne()).toBe('deferred')
      expect((await scanRow(scanId)).error).toMatchObject({ code: 'E_CATALOG' })
      await writeFile(paths.catalogIndexFile, catalog)
      await db.pool.query(`UPDATE scans SET error = NULL WHERE id = $1`, [scanId])
      expect(await worker().dispatchOne()).toBe('dispatched')
      row = await scanRow(scanId)
      expect(row.plan.modules.map((m: { id: string }) => m.id)).toEqual(['gitleaks'])
    })

    it('reprise : analyse « ingesting » sans tâche conclue ; tâche orpheline retirée de incoming', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      await db.pool.query(
        `UPDATE scans SET status = 'ingesting', job_id = NULL, started_at = now() - interval '10 minutes',
                error = '{"code":"E_SCAN_SOURCE","class":"input","message":"x"}' WHERE id = $1`, [scanId])
      const w = worker()
      expect(await w.recoverOrphans()).toBe(1)
      expect(await scanRow(scanId)).toMatchObject({ status: 'error', verdict: 'inconclusive' })

      const orphan = randomUUID()
      const path = join(cfg.scansDir, 'jobs', 'incoming', `${orphan}.json`)
      await writeFile(path, '{}')
      expect(await w.sweepIncoming()).toBe(0)
      const old = new Date(Date.now() - 5 * 60_000)
      await utimes(path, old, old)
      const s2 = await enqueueScan(db.pool, { projectId: p, ref: 'other', trigger: 'manual' })
      await w.dispatch()
      const kept = `${(await scanRow(s2.scanId)).job_id}.json`
      await utimes(join(cfg.scansDir, 'jobs', 'incoming', kept), old, old)
      expect(await w.sweepIncoming()).toBe(1)
      expect(await incoming()).toEqual([kept])
    })

    it('G11 : commit ou empreinte d’image différents du plan → non concluant, rien d’ingéré', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', commit: 'a'.repeat(40), trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      await runJob((await scanRow(scanId)).job_id)
      await w.collect()
      expect(await scanRow(scanId)).toMatchObject({ status: 'error', verdict: 'inconclusive', commit_sha: 'a'.repeat(40), error: { code: 'E_COMMIT_MISMATCH' } })
      expect(seen.ingest).toEqual([])

      const s2 = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      await w.dispatch()
      const job = (await scanRow(s2.scanId)).job_id
      await runJob(job)
      const file = join(cfg.scansDir, 'results', job, 'result.json')
      const res = JSON.parse(await readFile(file, 'utf8'))
      res.modules[0].image_digest = `sha256:${'e'.repeat(64)}`
      await writeFile(file, JSON.stringify(res))
      await w.collect()
      const mods = await moduleRows(s2.scanId)
      expect(mods.find(m => m.module_id === res.modules[0].id)).toMatchObject({ status: 'error', error_class: 'infra' })
      expect((await scanRow(s2.scanId)).verdict).toBe('inconclusive')
    })

    it('annulation entre la relecture et l’ingestion : jamais ressuscitée', async () => {
      const p = await newProject()
      const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      await runJob((await scanRow(scanId)).job_id)
      const original = integrations.decryptSecret
      // Annule pendant le calcul du masquage, après stillCurrent.
      const cred = await db.pool.query<{ id: string }>(`INSERT INTO credentials (kind, secret_enc, hint) VALUES ('token', '\\x01', '…abcd') RETURNING id`)
      await db.pool.query('UPDATE projects SET credential_id = $2 WHERE id = $1', [p, cred.rows[0]!.id])
      integrations.decryptSecret = async () => {
        await cancelScan(db.pool, scanId)
        throw new Error('x')
      }
      try {
        await w.collect()
      }
      finally {
        integrations.decryptSecret = original
      }
      expect(await scanRow(scanId)).toMatchObject({ status: 'cancelled', verdict: null })
    })

    it('fusion : jamais avec une analyse en file d’un autre quality gate', async () => {
      const p = await newProject()
      const a = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'schedule' })
      const g2 = await db.pool.query<{ id: string }>(
        `INSERT INTO gates (slug, rules) SELECT 'g-' || substr(md5(random()::text), 1, 8), rules FROM gates WHERE id = $1 RETURNING id`, [gate])
      await db.pool.query('UPDATE projects SET gate_id = $2 WHERE id = $1', [p, g2.rows[0]!.id])
      const b = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      expect(b.merged).toBe(false)
      expect(b.scanId).not.toBe(a.scanId)
    })
  })

  describe('rejeu à l’identique (G11) et annulation', () => {
    it('même commit, même plan ; module disparu constaté manquant ; tout disparu → non concluant sans tâche', async () => {
      const p = await newProject()
      const orig = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      await runJob((await scanRow(orig.scanId)).job_id)
      await w.tick()
      const origRow = await scanRow(orig.scanId)

      // Un catalogue plus récent ne change pas le plan rejoué.
      await setInstalled([{ id: 'gitleaks', version: '8.30.1' }, { id: 'trivy', version: '0.77.0' }])
      const replay = await enqueueScan(db.pool, { projectId: p, ref: 'ignored', trigger: 'replay', replayOf: orig.scanId })
      const r0 = await scanRow(replay.scanId)
      expect(r0).toMatchObject({ trigger: 'replay', replay_of: orig.scanId, commit_sha: COMMIT, ref: 'main', priority: 40 })
      expect(r0.plan).toEqual(origRow.plan)
      await w.dispatch()
      const r1 = await scanRow(replay.scanId)
      const job = JSON.parse(await readFile(join(cfg.scansDir, 'jobs', 'incoming', `${r1.job_id}.json`), 'utf8')) as ScanJob
      expect(job.source).toMatchObject({ commit: COMMIT, ref: 'main' })
      expect(job.modules.map(m => m.id)).toEqual(['gitleaks'])
      expect((await moduleRows(replay.scanId)).map(m => [m.module_id, m.module_version, m.status])).toEqual([
        ['gitleaks', '8.30.1', 'pending'], ['trivy', '0.76.2', 'missing'],
      ])
      await runJob(r1.job_id)
      await w.tick()
      expect(await scanRow(replay.scanId)).toMatchObject({ status: 'done', verdict: 'inconclusive' })
      expect(seen.finalize.at(-1)).toEqual([replay.scanId, false])

      await setInstalled([])
      const replay2 = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'replay', replayOf: orig.scanId })
      expect(replay2.merged).toBe(false)
      expect(await w.dispatchOne()).toBe('finished')
      expect(await scanRow(replay2.scanId)).toMatchObject({ status: 'done', verdict: 'inconclusive', job_id: null })
    })

    it('annulation en file, déposée (tâche retirée par le worker), en cours (résultat ignoré) ; terminée refusée', async () => {
      const [p1, p2, p3] = [await newProject(), await newProject(), await newProject()]
      const q = await enqueueScan(db.pool, { projectId: p1, ref: 'main', trigger: 'manual' })
      expect(await cancelScan(db.pool, q.scanId)).toBe(true)
      expect(await cancelScan(db.pool, q.scanId)).toBe(false)
      const d = await enqueueScan(db.pool, { projectId: p2, ref: 'main', trigger: 'manual' })
      const r = await enqueueScan(db.pool, { projectId: p3, ref: 'main', trigger: 'manual' })
      const w = worker()
      await w.dispatch()
      const dJob = (await scanRow(d.scanId)).job_id
      const rJob = (await scanRow(r.scanId)).job_id
      const rTaken = await takeJob(rJob)
      await w.collect()
      expect((await scanRow(r.scanId)).status).toBe('running')
      expect(await cancelScan(db.pool, d.scanId)).toBe(true)
      expect(await cancelScan(db.pool, r.scanId)).toBe(true)
      await w.tick()
      expect(await incoming()).not.toContain(`${dJob}.json`)
      await writeFile(join(cfg.scansDir, 'jobs', 'incoming', `${rJob}.json`), JSON.stringify(rTaken))
      await runJob(rJob)
      await w.tick()
      expect(await scanRow(r.scanId)).toMatchObject({ status: 'cancelled', verdict: null })
      expect((await moduleRows(r.scanId)).every(m => m.status === 'skipped')).toBe(true)
    })
  })

  describe('service, journaux et API', () => {
    it('service : passe, planification (A) avec enqueueScan, signe de vie, arrêt propre', async () => {
      const svc = new WorkerService({ pool: db.pool, cfg: { ...cfg, tickMs: 20, scheduleMs: 100_000 }, paths, integrations, version: '0.3.0', log: m => logs.push(m) })
      const before = seen.schedules
      const run = svc.start()
      await new Promise(resolve => setTimeout(resolve, 120))
      await svc.stop()
      await run
      expect(seen.schedules).toBe(before + 1)
      const beat = JSON.parse(await readFile(cfg.heartbeatFile, 'utf8'))
      expect(beat).toMatchObject({ pid: process.pid, version: '0.3.0' })
      expect(Date.now() - Date.parse(beat.at)).toBeLessThan(5000)

      // Une planification qui lève n'arrête pas la boucle.
      const down = async () => {
        throw new Error('forge down')
      }
      const failing = new WorkerService({ pool: db.pool, cfg, paths, integrations: { ...integrations, runProjectSchedules: down }, log: m => logs.push(m) })
      await failing.iterate()
      expect(logs.some(l => l.includes('schedules failed: forge down'))).toBe(true)
      // Bouchons par défaut : planification sans effet, verdict non concluant.
      await new WorkerService({ pool: db.pool, cfg, paths, integrations: defaultIntegrations, log: () => {} }).iterate()
    })

    it('journaux orphelins purgés ; bouchon du verdict non concluant', async () => {
      await mkdir(join(cfg.scanLogsDir, randomUUID()), { recursive: true })
      await mkdir(join(cfg.scanLogsDir, 'pas-un-uuid'), { recursive: true })
      const kept = (await db.pool.query<{ id: string }>('SELECT id FROM scans LIMIT 1')).rows[0]!.id
      await mkdir(join(cfg.scanLogsDir, kept), { recursive: true })
      expect(await worker().purgeOrphanLogs()).toBeGreaterThanOrEqual(1)
      const left = await readdir(cfg.scanLogsDir)
      expect(left).toContain(kept)
      expect(left).toContain('pas-un-uuid')
      const v = await defaultIntegrations.evaluateGate(db.pool, kept)
      expect(v).toMatchObject({ verdict: 'inconclusive', reasons: [] })
      expect(await defaultIntegrations.ingestModuleOutputs(db.pool, { scanId: kept, moduleId: 'x', resultDir: '/', outputs: {} })).toEqual({ count: 0, newCount: 0, errors: [] })
      await expect(defaultIntegrations.decryptSecret(db.pool, kept)).rejects.toThrow()
    })

    describe('API /api/scans', () => {
      let server: Server
      let base: string
      let role: 'viewer' | 'operator' = 'operator'
      let userId: number

      beforeAll(async () => {
        await createUser(db.pool, { username: 'ops', role: 'operator', password: 'ops-long-password', mustChangePassword: false })
        userId = Number((await db.pool.query<{ id: string }>(`SELECT id FROM users WHERE username = 'ops'`)).rows[0]!.id)
        process.env.SCANORIA_SCAN_LOGS_DIR = cfg.scanLogsDir
        const app = createApp()
        app.use(defineEventHandler((event) => {
          event.context.auth = { user: { id: userId, username: 'ops', displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
        }))
        const router = createRouter()
        const routes: [string, string, string][] = [
          ['get', '/api/scans', 'index.get'], ['post', '/api/scans', 'index.post'], ['get', '/api/scans/:id', '[id]/index.get'],
          ['post', '/api/scans/:id/cancel', '[id]/cancel.post'], ['post', '/api/scans/:id/retry', '[id]/retry.post'],
          ['post', '/api/scans/:id/replay', '[id]/replay.post'], ['get', '/api/scans/:id/modules/:module/log', '[id]/modules/[module]/log.get'],
        ]
        for (const [method, path, file] of routes) {
          const handler = (await import(fileURLToPath(new URL(`../../server/api/scans/${file}.ts`, import.meta.url)))).default as EventHandler
          router[method as 'get'](path, handler)
        }
        app.use(router)
        server = createServer(toNodeListener(app))
        await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
        const addr = server.address()
        base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
      })
      afterAll(async () => {
        delete process.env.SCANORIA_SCAN_LOGS_DIR
        if (!server) return
        server.closeAllConnections()
        await new Promise(resolve => server.close(resolve))
      })

      async function call(method: string, path: string, json?: unknown) {
        const res = await fetch(`${base}${path}`, { method, headers: json ? { 'content-type': 'application/json' } : {}, body: json ? JSON.stringify(json) : undefined })
        const text = await res.text()
        let data: Record<string, unknown> & { data?: { code?: string } }
        try {
          data = JSON.parse(text)
        }
        catch {
          data = { text } as never
        }
        return { status: res.status, data, headers: res.headers }
      }

      it('mise en file, détail, liste, relance, rejeu, annulation, journal ; droits et audit', async () => {
        role = 'operator'
        const p = await newProject({ default_branch: 'develop' })
        const created = await call('POST', '/api/scans', { project_id: p })
        expect(created.status).toBe(202)
        const scanId = created.data.scan_id as string
        expect((await scanRow(scanId)).ref).toBe('develop')
        expect((await call('POST', '/api/scans', { project_id: p })).status).toBe(200)
        expect((await call('POST', '/api/scans', { project_id: randomUUID() })).data.data?.code).toBe('E_SCAN_PROJECT_NOT_FOUND')
        expect((await call('POST', '/api/scans', { project_id: p, ref: '--upload-pack=x' })).data.data?.code).toBe('E_SCAN_REF')
        expect((await call('POST', '/api/scans', { project_id: p, extra: 1 })).status).toBe(400)

        const detail = await call('GET', `/api/scans/${scanId}`)
        expect(detail.data).toMatchObject({ id: scanId, status: 'queued', queue_position: 1, requested_by_username: 'ops', by_api_token: false, modules: [] })
        expect(detail.data).not.toHaveProperty('job_id')
        expect((await call('GET', '/api/scans/not-a-uuid')).data.data?.code).toBe('E_SCAN_NOT_FOUND')
        expect((await call('GET', `/api/scans/${randomUUID()}`)).status).toBe(404)
        const active = await call('GET', '/api/scans?status=active')
        expect((active.data.items as { id: string }[]).map(i => i.id)).toContain(scanId)
        expect((await call('GET', '/api/scans?status=bogus')).status).toBe(400)

        const w = worker()
        await w.dispatch()
        await runJob((await scanRow(scanId)).job_id)
        await w.tick()
        const log = await call('GET', `/api/scans/${scanId}/modules/gitleaks/log`)
        expect(log.status).toBe(200)
        expect(log.data.text).toBe('log gitleaks\n')
        expect(log.headers.get('content-disposition')).toMatch(/^attachment; filename="scan-/)
        expect((await call('GET', `/api/scans/${scanId}/modules/Bad/log`)).status).toBe(404)
        expect((await call('GET', `/api/scans/${scanId}/modules/absent/log`)).data.data?.code).toBe('E_SCAN_LOG')

        expect((await call('POST', `/api/scans/${scanId}/cancel`)).data.data?.code).toBe('E_SCAN_STATE')
        const retry = await call('POST', `/api/scans/${scanId}/retry`)
        expect(retry.status).toBe(202)
        expect(await scanRow(retry.data.scan_id as string)).toMatchObject({ trigger: 'manual', ref: 'develop', plan: null })
        const replay = await call('POST', `/api/scans/${scanId}/replay`)
        expect(replay.status).toBe(202)
        expect(await scanRow(replay.data.scan_id as string)).toMatchObject({ trigger: 'replay', replay_of: scanId, commit_sha: COMMIT })
        expect((await call('POST', `/api/scans/${retry.data.scan_id}/replay`)).data.data?.code).toBe('E_SCAN_REPLAY')
        expect((await call('POST', `/api/scans/${retry.data.scan_id}/cancel`)).status).toBe(200)
        expect((await call('POST', `/api/scans/${randomUUID()}/cancel`)).status).toBe(404)
        expect((await call('POST', `/api/scans/${randomUUID()}/retry`)).status).toBe(404)
        expect((await call('POST', `/api/scans/${randomUUID()}/replay`)).status).toBe(404)

        const audit = await db.pool.query<{ action: string, outcome: string }>(`SELECT action, outcome FROM audit_log WHERE action LIKE 'scan.%' ORDER BY id`)
        expect(audit.rows.map(a => `${a.action}:${a.outcome}`)).toEqual(expect.arrayContaining([
          'scan.create:success', 'scan.create:failure', 'scan.cancel:failure', 'scan.retry:success', 'scan.replay:success', 'scan.replay:failure', 'scan.cancel:success',
        ]))

        role = 'viewer'
        expect((await call('GET', '/api/scans')).status).toBe(200)
        expect((await call('POST', '/api/scans', { project_id: p })).status).toBe(403)
        expect((await call('POST', `/api/scans/${scanId}/replay`)).status).toBe(403)
        expect((await call('POST', `/api/scans/${scanId}/cancel`)).status).toBe(403)
      })

      it('liste filtrée et ordre de la file ; position dans la file', async () => {
        const p = await newProject()
        const a = await enqueueScan(db.pool, { projectId: p, ref: 'a', trigger: 'schedule' })
        const b = await enqueueScan(db.pool, { projectId: p, ref: 'b', trigger: 'release' })
        const list = await listScans(db.pool, { project: p, status: 'active', limit: 50, offset: 0 })
        expect(list.items.map(i => i.id)).toEqual([b.scanId, a.scanId])
        expect((await getScan(db.pool, a.scanId))!.queue_position).toBe(2)
        expect((await getScan(db.pool, b.scanId))!.queue_position).toBe(1)
        const hist = await listScans(db.pool, { project: p, trigger: 'release', verdict: undefined, limit: 1, offset: 0 })
        expect(hist).toMatchObject({ total: 1 })
        expect((await listScans(db.pool, { project: p, status: 'done', limit: 50, offset: 0 })).total).toBe(0)
        expect((await listScans(db.pool, { verdict: 'passed', limit: 50, offset: 0 })).total).toBeGreaterThan(0)
        expect(await getScan(db.pool, randomUUID())).toBeNull()
      })
    })
  })

  it('tâches temporaires : une écriture qui échoue ne laisse rien et l’analyse reste en file', async () => {
    const p = await newProject()
    const { scanId } = await enqueueScan(db.pool, { projectId: p, ref: 'main', trigger: 'manual' })
    const broken = worker({ scansDir: join(root, 'absent') })
    await expect(broken.dispatchOne()).rejects.toThrow()
    expect(await scanRow(scanId)).toMatchObject({ status: 'queued', job_id: null })
    await utimes(cfg.runnerStateFile, new Date(), new Date())
  })
})
