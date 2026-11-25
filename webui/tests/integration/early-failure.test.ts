// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// V8 (contrat 35) contre PostgreSQL avec l'ingestion et le quality gate réels :
// un secret trouvé par un module terminé est publié avant la fin de
// l'analyse ; un module en erreur ou inconnu n'anticipe rien ; une seule
// publication ; jamais de verdict favorable anticipé.

import { randomBytes, randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { finalizeScanFindings, ingestModuleOutputs } from '../../server/findings/ingest'
import { evaluateGate } from '../../server/gates/evaluate'
import { CERTAIN_REASONS, certainReasons, checkEarlyFailure, readProgress } from '../../server/scans/early'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))

describe.skipIf(!DATABASE_URL)('verdict défavorable anticipé (V8)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  const scans = () => join(root, 'scans')
  const published: { scanId: string, reasons: string[] }[] = []
  const deps = {
    ingestModuleOutputs, finalizeScanFindings, evaluateGate,
    publish: async (_db: unknown, scanId: string, reasons: string[]) => {
      published.push({ scanId, reasons })
    },
  }

  async function runningScan(modules: string[]) {
    const jobId = randomUUID()
    const r = await db.pool.query<{ id: string, plan: unknown }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, job_id, started_at, plan)
       VALUES ($1, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'webhook', 60, 'refs/pull/1/head', $2,
               (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), 'running', $3, now(), $4)
       RETURNING id, plan`,
      [projectId, randomBytes(20).toString('hex'), jobId, JSON.stringify({ modules: modules.map(id => ({ id })) })])
    for (const m of modules) await db.pool.query(`INSERT INTO scan_modules (scan_id, module_id, module_version, status) VALUES ($1, $2, '1.0.0', 'running')`, [r.rows[0]!.id, m])
    return { id: r.rows[0]!.id, job_id: jobId, plan: r.rows[0]!.plan }
  }

  async function progress(jobId: string, modules: { id: string, status: string, sarif?: unknown }[]) {
    const dir = join(scans(), 'results', jobId)
    await mkdir(dir, { recursive: true })
    for (const m of modules) {
      if (!m.sarif) continue
      await mkdir(join(dir, m.id), { recursive: true })
      await writeFile(join(dir, m.id, 'result.sarif'), JSON.stringify(m.sarif))
    }
    await writeFile(join(dir, 'progress.json'), JSON.stringify({
      schema: 1, modules: modules.map(m => ({ id: m.id, status: m.status, outputs: m.sarif ? { sarif: `${m.id}/result.sarif` } : {} })),
    }))
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-early-'))
    const index = { schema: 1, version: 1, modules: [{ id: 'gitleaks', version: '1.0.0', categories: ['secrets'] }, { id: 'trivy', version: '1.0.0', categories: ['sca'] }] }
    await writeFile(join(root, 'catalog-index.json'), JSON.stringify(index))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_CATALOG_INDEX_FILE: join(root, 'catalog-index.json') }))
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, profile_id, gate_id)
       VALUES ('demo', 'Démo', 'git', 'https://forge.exemple.test/demo.git', (SELECT id FROM profiles WHERE slug = 'rapide'),
               (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)).rows[0]!.id
  })

  afterAll(async () => {
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('raisons certaines seulement', () => {
    expect(CERTAIN_REASONS).toEqual(expect.arrayContaining(['secret', 'malicious-package']))
    expect(certainReasons({ reasons: [
      { code: 'secret', blocking: true }, { code: 'module-error', blocking: true }, { code: 'vuln', blocking: true }, { code: 'kev', blocking: false },
    ] } as never)).toEqual(['secret'])
  })

  it('secret trouvé par un module terminé : échec publié pendant que l’autre tourne encore, une seule fois', async () => {
    const scan = await runningScan(['gitleaks', 'trivy'])
    const seen = new Set<string>()
    // Rien de terminé : rien d'anticipé.
    expect(await checkEarlyFailure(db.pool, deps, scan, scans(), seen)).toBeNull()
    const sarif = JSON.parse(await readFile(`${MODULES}gitleaks/tests/recorded.sarif`, 'utf8'))
    await progress(scan.job_id, [{ id: 'gitleaks', status: 'ok', sarif }])
    expect(await checkEarlyFailure(db.pool, deps, scan, scans(), seen)).toEqual(['secret'])
    const row = await db.pool.query('SELECT status, early_failure, verdict FROM scans WHERE id = $1', [scan.id])
    expect(row.rows[0].status).toBe('running')
    expect(row.rows[0].verdict).toBeNull()
    expect(row.rows[0].early_failure).toMatchObject({ reasons: ['secret'], modules: ['gitleaks'] })
    expect(row.rows[0].early_failure.finding_ids.length).toBeGreaterThan(0)
    expect(published).toEqual([{ scanId: scan.id, reasons: ['secret'] }])
    // Nouvelle passe : déjà publié, rien de plus.
    expect(await checkEarlyFailure(db.pool, deps, scan, scans(), new Set())).toBeNull()
    expect(published).toHaveLength(1)
  })

  it('module en erreur, hors plan ou sans sortie : rien d’anticipé ; progress.json hostile ignoré', async () => {
    const scan = await runningScan(['gitleaks', 'trivy'])
    const sarif = JSON.parse(await readFile(`${MODULES}gitleaks/tests/recorded.sarif`, 'utf8'))
    await progress(scan.job_id, [{ id: 'gitleaks', status: 'error', sarif }, { id: 'intrus', status: 'ok', sarif }, { id: 'trivy', status: 'ok' }])
    expect(await checkEarlyFailure(db.pool, deps, scan, scans(), new Set())).toBeNull()
    const dir = join(scans(), 'results', scan.job_id)
    await writeFile(join(dir, 'progress.json'), JSON.stringify({ schema: 1, modules: [{ id: 'gitleaks', status: 'ok', outputs: { sarif: '../../../etc/passwd' } }] }))
    expect(await readProgress(scans(), scan.job_id)).toBeNull()
    await writeFile(join(dir, 'progress.json'), 'pas du json')
    expect(await readProgress(scans(), scan.job_id)).toBeNull()
    expect(published.filter(p => p.scanId === scan.id)).toHaveLength(0)
  })

  it('analyse d’essai ou terminée : jamais', async () => {
    const scan = await runningScan(['gitleaks'])
    await db.pool.query(`UPDATE scans SET status = 'done' WHERE id = $1`, [scan.id])
    expect(await checkEarlyFailure(db.pool, deps, scan, scans(), new Set())).toBeNull()
  })
})
