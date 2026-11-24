// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 14 (0.5) contre un vrai PostgreSQL 16 : ingestion du SBOM de Syft
// (sbom_components, couverture G15), refus sans ingestion partielle, lien
// Dependency-Track, dernier SBOM d'un projet, API de l'onglet SBOM et export
// CycloneDX (audité).

import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, defineEventHandler, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { ingestSbom, ingestSbomFile, ingestSbomOutput, latestSbom, latestSbomScan, recordDtrackProject, SbomError } from '../../server/sbom/ingest'
import { dtrackProjectUrl, sbomPage, sbomQuery } from '../../server/sbom/api'
import { defaultIntegrations } from '../../server/scans/integrations'

const MODULES = fileURLToPath(new URL('../../../modules/', import.meta.url))
const recorded = async (id: string) => JSON.parse(await readFile(`${MODULES}${id}/tests/recorded.cdx.json`, 'utf8')) as Record<string, unknown>
const DTRACK = '3d7c8f2a-5b1e-4c9d-a6f0-2e8b7d4c1a90'

describe.skipIf(!DATABASE_URL)('SBOM des analyses (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let scanNo = 0

  async function newScan(status = 'ingesting'): Promise<string> {
    scanNo++
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, started_at, finished_at)
       VALUES ($1, $2::int, 'manual', 50, 'main', $3, (SELECT id FROM profiles WHERE slug = 'complet'), (SELECT id FROM gates WHERE slug = 'defaut'),
               $4::text, now(), CASE WHEN $4::text = 'done' THEN now() + make_interval(secs => $2::int) END) RETURNING id`,
      [projectId, scanNo, 'a'.repeat(40), status])
    return r.rows[0]!.id
  }
  const coverage = async (id: string) => (await db.pool.query<{ c: Record<string, unknown> | null }>('SELECT coverage AS c FROM scans WHERE id = $1', [id])).rows[0]!.c
  const count = async (id: string) => (await db.pool.query<{ n: number }>('SELECT count(*)::int AS n FROM sbom_components WHERE scan_id = $1', [id])).rows[0]!.n

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-sbom-'))
    await writeFile(join(root, 'state.json'), JSON.stringify({
      version: 1, updated_at: '2026-11-24T08:00:00Z', operations: [],
      modules: [{ id: 'dependency-track', version: '4.14.7', type: 'service', status: 'healthy', enabled: true, installed_at: '2026-11-24T08:00:00Z',
        options: {}, testbed: null, route: { hostname: 'dtrack.analyse.exemple.test', url: 'https://dtrack.analyse.exemple.test/' }, last_error: null }],
    }))
    setConfig(loadConfig({ NUXT_DATABASE_URL: db.url, NUXT_MODULES_STATE_FILE: join(root, 'state.json') }))
    const p = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, profile_id, gate_id)
       VALUES ('demo', 'Démo', 'git', 'https://forge.exemple.test/demo.git', (SELECT id FROM profiles WHERE slug = 'complet'),
               (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)
    projectId = p.rows[0]!.id
  })

  afterAll(async () => {
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('range le SBOM enregistré de Syft, remplace un relevé précédent et garde la couverture existante', async () => {
    const s = await newScan()
    await db.pool.query(`UPDATE scans SET coverage = '{"source": {"files": 3}}' WHERE id = $1`, [s])
    const cov = await ingestSbom(db.pool, { scanId: s, projectId, doc: await recorded('syft'), moduleId: 'syft' })
    expect(cov).toMatchObject({ components: 3, ignored_no_purl: 0 })
    const rows = (await db.pool.query('SELECT purl, ecosystem, name, version, licenses, direct, paths FROM sbom_components WHERE scan_id = $1 ORDER BY purl', [s])).rows
    expect(rows).toEqual([
      { purl: 'pkg:golang/github.com/google/uuid@v1.6.0', ecosystem: 'golang', name: 'github.com/google/uuid', version: 'v1.6.0', licenses: [], direct: null, paths: ['go.mod'] },
      { purl: 'pkg:npm/minimist@1.2.8', ecosystem: 'npm', name: 'minimist', version: '1.2.8', licenses: ['MIT'], direct: null, paths: ['package-lock.json'] },
      { purl: 'pkg:pypi/six@1.17.0', ecosystem: 'pypi', name: 'six', version: '1.17.0', licenses: [], direct: null, paths: ['requirements.txt'] },
    ])
    expect(await coverage(s)).toMatchObject({ source: { files: 3 }, sbom: { components: 3, module: 'syft', spec_version: '1.6' } })
    // Rejeu (relance de l'ingestion) : aucun doublon, relevé remplacé.
    await ingestSbom(db.pool, { scanId: s, projectId, doc: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'a', purl: 'pkg:npm/a@1' }, { name: 'sans purl' }] }, moduleId: 'syft' })
    expect(await count(s)).toBe(1)
    expect(await coverage(s)).toMatchObject({ sbom: { components: 1, ignored_no_purl: 1 } })
  })

  it('document invalide ou trop grand : rien n’est rangé, l’ancien relevé reste intact', async () => {
    const s = await newScan()
    await ingestSbom(db.pool, { scanId: s, projectId, doc: await recorded('syft') })
    await expect(ingestSbom(db.pool, { scanId: s, projectId, doc: { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'a', purl: 'pkg:npm/a@1' }, 'x'] } }))
      .rejects.toBeInstanceOf(SbomError)
    const many = Array.from({ length: 50_001 }, (_, i) => ({ name: `p${i}`, purl: `pkg:npm/p${i}@1` }))
    await expect(ingestSbom(db.pool, { scanId: s, projectId, doc: { bomFormat: 'CycloneDX', specVersion: '1.6', components: many } }))
      .rejects.toThrow(/more than 50000/)
    expect(await count(s)).toBe(3)
  })

  it('50 000 composants : rangés par lots, en une transaction', async () => {
    const s = await newScan()
    const many = Array.from({ length: 50_000 }, (_, i) => ({ name: `p${i}`, purl: `pkg:npm/p${i}@1`, licenses: [{ license: { id: 'MIT' } }] }))
    await ingestSbom(db.pool, { scanId: s, projectId, doc: { bomFormat: 'CycloneDX', specVersion: '1.6', components: many } })
    expect(await count(s)).toBe(50_000)
  }, 60_000)

  it('sortie d’un module (worker) : premier SBOM rangé, suivants ignorés, dtrack-upload rattache le projet', async () => {
    const s = await newScan()
    const dir = join(root, 'results', s)
    await mkdir(join(dir, 'syft'), { recursive: true })
    await mkdir(join(dir, 'dtrack-upload'), { recursive: true })
    await mkdir(join(dir, 'trivy'), { recursive: true })
    await writeFile(join(dir, 'syft', 'sbom.cdx.json'), JSON.stringify(await recorded('syft')))
    await writeFile(join(dir, 'dtrack-upload', 'dtrack.cdx.json'), JSON.stringify(await recorded('dtrack-upload')))
    await writeFile(join(dir, 'trivy', 'sbom.cdx.json'), JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'z', purl: 'pkg:npm/z@1' }] }))
    const ingest = defaultIntegrations.ingestSbomOutput!
    expect(await ingest(db.pool, { scanId: s, projectId, moduleId: 'dtrack-upload', resultDir: dir, path: 'dtrack-upload/dtrack.cdx.json' })).toBe('linked')
    expect(await ingest(db.pool, { scanId: s, projectId, moduleId: 'syft', resultDir: dir, path: 'syft/sbom.cdx.json' })).toBe('ingested')
    expect(await ingestSbomFile(db.pool, { scanId: s, projectId, moduleId: 'trivy', resultDir: dir, path: 'trivy/sbom.cdx.json' })).toBe('ignored')
    expect(await count(s)).toBe(3)
    expect(await coverage(s)).toMatchObject({ sbom: { components: 3, module: 'syft', dtrack_project: DTRACK } })
    // Sortie illisible, hors du répertoire ou par lien : refusée (module non concluant).
    await symlink(join(dir, 'syft', 'sbom.cdx.json'), join(dir, 'lien.json'))
    await writeFile(join(dir, 'casse.json'), '{')
    for (const path of ['lien.json', 'casse.json', '../x.json', 'absent.json']) {
      await expect(ingestSbomFile(db.pool, { scanId: s, projectId, moduleId: 'syft', resultDir: dir, path })).rejects.toBeInstanceOf(SbomError)
    }
    // Une sortie dtrack-upload malformée n'est pas acceptée.
    await expect(ingestSbomOutput(db.pool, { scanId: s, projectId, moduleId: 'dtrack-upload',
      doc: { bomFormat: 'CycloneDX', specVersion: '9', metadata: { properties: [{ name: 'scanoria:dtrack:project', value: DTRACK }] } } })).rejects.toBeInstanceOf(SbomError)
    await recordDtrackProject(db.pool, s, 'pas-un-uuid')
    expect(await coverage(s)).toMatchObject({ sbom: { dtrack_project: DTRACK } })
  })

  it('dernier SBOM d’un projet : analyse terminée la plus récente qui en a un', async () => {
    const other = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, repo_url, profile_id, gate_id)
       VALUES ('vide', 'Vide', 'git', 'https://forge.exemple.test/vide.git', (SELECT id FROM profiles WHERE slug = 'complet'),
               (SELECT id FROM gates WHERE slug = 'defaut')) RETURNING id`)
    expect(await latestSbom(db.pool, other.rows[0]!.id)).toBeNull()
    const old = await newScan('done')
    await ingestSbom(db.pool, { scanId: old, projectId, doc: await recorded('syft') })
    const recent = await newScan('done')
    await ingestSbom(db.pool, { scanId: recent, projectId, doc: { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'a', purl: 'pkg:npm/a@2' }] } })
    const running = await newScan('running')
    await ingestSbom(db.pool, { scanId: running, projectId, doc: await recorded('syft') })
    await newScan('done') // terminée, sans SBOM
    expect(await latestSbomScan(db.pool, projectId)).toBe(recent)
    const latest = await latestSbom(db.pool, projectId)
    expect(latest).toMatchObject({ scanId: recent, components: [{ purl: 'pkg:npm/a@2', name: 'a', published_at: null }] })
  })

  it('page de l’onglet : filtres, tri, pagination, facettes, lien Dependency-Track', async () => {
    const s = await newScan('done')
    await ingestSbom(db.pool, { scanId: s, projectId, doc: {
      bomFormat: 'CycloneDX', specVersion: '1.6',
      metadata: { component: { 'bom-ref': 'root', 'name': 'app' } },
      dependencies: [{ ref: 'root', dependsOn: ['b'] }],
      components: [
        { 'bom-ref': 'a', 'name': 'alpha', 'purl': 'pkg:npm/alpha@1.0.0', 'licenses': [{ license: { id: 'MIT' } }] },
        { 'bom-ref': 'b', 'name': 'beta_x', 'purl': 'pkg:pypi/beta_x@2.0', 'licenses': [{ license: { id: 'Apache-2.0' } }] },
        { 'bom-ref': 'c', 'name': 'gamma', 'purl': 'pkg:npm/gamma@0.1.0', 'licenses': [{ license: { id: 'MIT' } }] },
      ],
    } })
    const row = { id: s, project_id: projectId, coverage: await coverage(s) }
    const page = (q: Record<string, unknown>) => sbomPage(db.pool, row, sbomQuery.parse(q), join(root, 'state.json'))
    const all = await page({})
    expect(all).toMatchObject({ total: 3, matched: 3, dtrack: null })
    expect(all.components.map(c => c.name)).toEqual(['alpha', 'beta-x', 'gamma'])
    expect(all.ecosystems).toEqual([{ ecosystem: 'npm', count: 2 }, { ecosystem: 'pypi', count: 1 }])
    expect(all.licenses).toEqual([{ license: 'MIT', count: 2 }, { license: 'Apache-2.0', count: 1 }])
    expect((await page({ ecosystem: 'npm', sort: 'name', order: 'desc' })).components.map(c => c.name)).toEqual(['gamma', 'alpha'])
    expect((await page({ license: 'Apache-2.0' })).components.map(c => c.name)).toEqual(['beta-x'])
    expect((await page({ direct: 'true' })).components.map(c => c.name)).toEqual(['beta-x'])
    expect((await page({ direct: 'false' })).matched).toBe(2)
    expect((await page({ q: 'GAM' })).components.map(c => c.name)).toEqual(['gamma'])
    expect((await page({ q: '%' })).matched).toBe(0)
    const p2 = await page({ per_page: '2', page: '2', sort: 'version' })
    expect(p2).toMatchObject({ matched: 3, page: 2 })
    expect(p2.components.map(c => c.version)).toEqual(['2.0'])
    await recordDtrackProject(db.pool, s, DTRACK)
    const linked = await sbomPage(db.pool, { ...row, coverage: await coverage(s) }, sbomQuery.parse({}), join(root, 'state.json'))
    expect(linked.dtrack).toEqual({ project: DTRACK, url: `https://dtrack.analyse.exemple.test/projects/${DTRACK}` })
    expect(await dtrackProjectUrl(DTRACK, join(root, 'absent.json'))).toBeNull()
    expect(() => sbomQuery.parse({ sort: 'purl; DROP' })).toThrow()
    expect(() => sbomQuery.parse({ per_page: '500' })).toThrow()
    expect(() => sbomQuery.parse({ other: '1' })).toThrow()
  })

  describe('API', () => {
    let server: Server
    let base: string
    let role: 'viewer' | null = 'viewer'
    let scanId: string

    beforeAll(async () => {
      const app = createApp()
      app.use(defineEventHandler((event) => {
        if (role) event.context.auth = { user: { id: 1, username: 'lecteur', displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
      }))
      const router = createRouter()
      router.get('/api/scans/:id/sbom', (await import('../../server/api/scans/[id]/sbom/index.get')).default as EventHandler)
      router.get('/api/scans/:id/sbom/export', (await import('../../server/api/scans/[id]/sbom/export.get')).default as EventHandler)
      app.use(router)
      server = createServer(toNodeListener(app))
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      const addr = server.address()
      base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
      scanId = await newScan('done')
      await ingestSbom(db.pool, { scanId, projectId, doc: await recorded('syft') })
      await recordDtrackProject(db.pool, scanId, DTRACK)
    })
    afterAll(async () => {
      if (!server) return
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    })

    const get = async (path: string) => {
      const res = await fetch(`${base}${path}`)
      return { status: res.status, text: await res.text(), headers: res.headers }
    }

    it('liste : lecteur autorisé, anonyme refusé, paramètres validés', async () => {
      role = 'viewer'
      const r = await get(`/api/scans/${scanId}/sbom?ecosystem=npm`)
      expect(r.status).toBe(200)
      const body = JSON.parse(r.text)
      expect(body).toMatchObject({ total: 3, matched: 1, components: [{ name: 'minimist' }], dtrack: { project: DTRACK } })
      expect((await get(`/api/scans/${scanId}/sbom?sort=nope`)).status).toBe(400)
      expect((await get('/api/scans/pas-un-uuid/sbom')).status).toBe(404)
      expect((await get(`/api/scans/${crypto.randomUUID()}/sbom`)).status).toBe(404)
      role = null
      expect((await get(`/api/scans/${scanId}/sbom`)).status).toBe(401)
    })

    it('export CycloneDX 1.6 téléchargeable et audité ; rien à exporter sans SBOM', async () => {
      role = 'viewer'
      const r = await get(`/api/scans/${scanId}/sbom/export`)
      expect(r.status).toBe(200)
      expect(r.headers.get('content-type')).toContain('application/vnd.cyclonedx+json')
      expect(r.headers.get('content-disposition')).toMatch(/^attachment; filename="demo-\d+\.cdx\.json"$/)
      const doc = JSON.parse(r.text)
      expect(doc).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.6' })
      expect(doc.components.map((c: { purl: string }) => c.purl)).toContain('pkg:npm/minimist@1.2.8')
      const audit = await db.pool.query(`SELECT details FROM audit_log WHERE action = 'scan.sbom-export' AND target_id = $1`, [scanId])
      expect(audit.rows).toEqual([{ details: { components: 3 } }])
      const empty = await newScan('done')
      expect((await get(`/api/scans/${empty}/sbom/export`)).status).toBe(404)
    })
  })
})
