// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.7 (K2, K4) contre un vrai PostgreSQL 16 : le commit de base d'une analyse
// de PR est figé dans le plan (G11) et transmis au runner (pr_base), qui en
// tire le diff des modules scan.pr_diff ; hors PR, ou base mal formée, rien.

import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { VerdictDetails } from '#shared/analysis'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadWorkerConfig, type WorkerConfig } from '../../server/scans/config'
import { enqueueScan } from '../../server/scans/enqueue'
import { pendingGate, type Integrations } from '../../server/scans/integrations'
import { ScanWorker } from '../../server/scans/worker'
import type { ScanJob } from '../../server/scans/contract'
import { parsePlan } from '../../server/scans/plan'

const HEAD = 'c'.repeat(40)
const BASE = 'b'.repeat(40)
const DIGEST = `sha256:${'d'.repeat(64)}`

describe.skipIf(!DATABASE_URL)('commit de base des analyses de PR (K2, K4, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let cfg: WorkerConfig
  let paths: { modulesStateFile: string, catalogIndexFile: string }
  let project: string

  const integrations: Integrations = {
    decryptSecret: async () => {
      throw new Error('none')
    },
    ingestModuleOutputs: async () => ({ count: 0, newCount: 0, errors: [] }),
    ingestSbomOutput: async () => {},
    finalizeScanFindings: async () => {},
    evaluateGate: async (pool, scanId) => ({ ...(await pendingGate(pool, scanId)), verdict: 'passed' as VerdictDetails['verdict'] }),
    enqueueAiTask: async () => null,
    runProjectSchedules: async () => {},
  }

  async function dispatch(scanId: string): Promise<{ job: ScanJob, plan: ReturnType<typeof parsePlan> }> {
    await db.pool.query(`UPDATE scans SET status = 'cancelled' WHERE status = 'queued' AND id <> $1`, [scanId])
    expect(await new ScanWorker(db.pool, cfg, paths, integrations, () => {}).dispatchOne()).toBe('dispatched')
    const row = (await db.pool.query<{ job_id: string, plan: unknown }>('SELECT job_id, plan FROM scans WHERE id = $1', [scanId])).rows[0]!
    const file = join(cfg.scansDir, 'jobs', 'incoming', `${row.job_id}.json`)
    const job = JSON.parse(await readFile(file, 'utf8')) as ScanJob
    await rm(file)
    await db.pool.query(`UPDATE scans SET status = 'done' WHERE id = $1`, [scanId])
    return { job, plan: parsePlan(row.plan) }
  }

  const pr = (base: unknown) => ({ number: 7, base_sha: base, base_ref: 'main', head_sha: HEAD, head_ref: 'fonction', author: 'dev-une' })

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-prdiff-'))
    for (const d of ['scans/jobs/tmp', 'scans/jobs/incoming', 'scans/results', 'logs']) await mkdir(join(root, d), { recursive: true })
    cfg = { ...loadWorkerConfig({}), scansDir: join(root, 'scans'), runnerStateFile: join(root, 'runner.json'), scanLogsDir: join(root, 'logs'), retryBaseS: 0 }
    paths = { modulesStateFile: join(root, 'modules-state.json'), catalogIndexFile: join(root, 'catalog-index.json') }
    const lic = { spdx: 'MIT', restrictions: 'none' }
    await writeFile(paths.catalogIndexFile, JSON.stringify({
      schema: 1, version: 19, generated_at: '2026-11-25T00:00:00Z', packs: [],
      modules: [{
        id: 'pr-agent', name: 'PR-Agent', version: '0.50.0', type: 'scanner', categories: ['quality'], license: lic,
        requires: { modules: [], feeds: [] }, conflicts: [], image: `ghcr.io/exemple/pr-agent@${DIGEST}`,
        outputs: { sarif: { path: '/out/pr-agent.sarif', version: '2.1.0' } },
        scan: { inputs: ['repo'], command: ['x'], timeout_s: 900, network: 'ai-relay', pr_diff: 'required' },
      }],
    }))
    await writeFile(paths.modulesStateFile, JSON.stringify({
      version: 1, updated_at: '2026-11-25T08:00:00Z', operations: [],
      modules: [{ id: 'pr-agent', version: '0.50.0', type: 'scanner', status: 'healthy', enabled: true, installed_at: '2026-11-25T08:00:00Z', options: {}, testbed: null, route: null, last_error: null }],
    }))
    await writeFile(cfg.runnerStateFile, JSON.stringify({ slots: 4, busy: 0, updated_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') }))
    const complet = (await db.pool.query<{ id: string }>(`SELECT id FROM profiles WHERE slug = 'complet'`)).rows[0]!.id
    await db.pool.query(`UPDATE profiles SET categories = ARRAY['quality'] WHERE id = $1`, [complet])
    const gate = (await db.pool.query<{ id: string }>(`SELECT id FROM gates WHERE slug = 'defaut'`)).rows[0]!.id
    const slug = `p-${randomUUID().slice(0, 8)}`
    project = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, default_branch, profile_id, gate_id)
       VALUES ($1, $1, 'git', $2, 'main', $3, $4) RETURNING id`, [slug, `https://forge.exemple.test/exemple/${slug}.git`, complet, gate])).rows[0]!.id
  })

  afterAll(async () => {
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('analyse de PR : base figée dans le plan et transmise au runner', async () => {
    const s = await enqueueScan(db.pool, { projectId: project, ref: 'refs/pull/7/head', commit: HEAD, trigger: 'webhook', pullRequest: pr(BASE) })
    const { job, plan } = await dispatch(s.scanId)
    expect(plan?.source.pr_base).toBe(BASE)
    expect(job.pr_base).toBe(BASE)
    expect(job.modules.map(m => m.id)).toEqual(['pr-agent'])
  })

  it('hors PR, ou base mal formée : aucun commit de base', async () => {
    const a = await enqueueScan(db.pool, { projectId: project, ref: 'main', commit: HEAD, trigger: 'manual' })
    const r1 = await dispatch(a.scanId)
    expect(r1.job.pr_base).toBeUndefined()
    expect(r1.plan?.source.pr_base).toBeUndefined()
    const b = await enqueueScan(db.pool, { projectId: project, ref: 'refs/pull/8/head', commit: HEAD, trigger: 'webhook', pullRequest: pr('main; rm -rf /') })
    const r2 = await dispatch(b.scanId)
    expect(r2.job.pr_base).toBeUndefined()
  })
})
