// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Volet console de tests/b19-live.sh (0.5, contrat 14) : les sorties RÉELLES
// d'une analyse complète (runner, Syft, Grype et dtrack-upload en vrais
// conteneurs, Dependency-Track réel) sont ingérées comme par le worker, contre
// un vrai PostgreSQL 16. Sauté hors de b19-live (SCANORIA_SBOM_LIVE_RESULT
// désigne results/<tâche>/ publié par le runner).

import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { defaultIntegrations } from '../../server/scans/integrations'
import { latestSbom } from '../../server/sbom/ingest'

const RESULT = process.env.SCANORIA_SBOM_LIVE_RESULT ?? ''

describe.skipIf(!DATABASE_URL || !RESULT)('SBOM réel de b19-live (PostgreSQL réel)', () => {
  let db: TestDatabase
  let projectId: string
  let scanId: string
  let result: { modules: { id: string, status: string, outputs: Record<string, string> }[] }

  beforeAll(async () => {
    db = await createTestDatabase()
    result = JSON.parse(await readFile(join(RESULT, 'result.json'), 'utf8'))
    const p = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id)
       VALUES ('b19', 'b19-live', 'archive', (SELECT id FROM profiles WHERE slug = 'complet'), (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)
    projectId = p.rows[0]!.id
    const s = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, started_at)
       VALUES ($1, 1, 'manual', 50, 'archive', (SELECT id FROM profiles WHERE slug = 'complet'), (SELECT id FROM gates WHERE slug = 'defaut'), 'ingesting', now())
       RETURNING id`, [projectId])
    scanId = s.rows[0]!.id
  })
  afterAll(async () => {
    await db?.drop()
  })

  it('sorties CycloneDX de Syft et de dtrack-upload ingérées comme par le worker', async () => {
    const ingest = defaultIntegrations.ingestSbomOutput!
    const done: Record<string, unknown> = {}
    for (const m of result.modules) {
      expect(m.status, m.id).toBe('ok')
      if (m.outputs.cyclonedx) {
        done[m.id] = await ingest(db.pool, { scanId, projectId, moduleId: m.id, resultDir: RESULT, path: m.outputs.cyclonedx })
      }
    }
    expect(done).toEqual({ 'syft': 'ingested', 'dtrack-upload': 'linked' })
    await db.pool.query(`UPDATE scans SET status = 'done', finished_at = now() WHERE id = $1`, [scanId])
    const latest = await latestSbom(db.pool, projectId)
    expect(latest?.scanId).toBe(scanId)
    const byName = new Map(latest!.components.map(c => [c.name, c]))
    expect(byName.get('minimist')).toMatchObject({ ecosystem: 'npm', version: '1.2.5', purl: 'pkg:npm/minimist@1.2.5' })
    expect(byName.get('six')).toMatchObject({ ecosystem: 'pypi', version: '1.17.0' })
    expect(byName.get('github.com/google/uuid')).toMatchObject({ ecosystem: 'golang', version: 'v1.6.0' })
    expect(byName.get('minimist')!.paths.some(p => p.endsWith('package-lock.json'))).toBe(true)
    const cov = (await db.pool.query<{ c: { sbom: Record<string, unknown> } }>('SELECT coverage AS c FROM scans WHERE id = $1', [scanId])).rows[0]!.c
    expect(cov.sbom).toMatchObject({ module: 'syft', spec_version: '1.6' })
    expect(cov.sbom.dtrack_project).toMatch(/^[0-9a-f-]{36}$/)
    console.log(`b19-live : ${latest!.components.length} composant(s) rangé(s), couverture ${JSON.stringify(cov.sbom)}`)
  })
})
