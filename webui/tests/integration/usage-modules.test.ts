// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F14 contre un vrai PostgreSQL : recopie des relevés de l'état (contrat 11)
// sans doublon, purge à 90 jours, statistiques des scanners (médiane, p95,
// mesures absentes ignorées), courbes des modules permanents, modules
// inutilisés (dépendances exclues, G1) et API /api/usage.

import { randomUUID } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import type { CatalogIndex, InstalledModule } from '../../server/utils/catalog'
import { parseModulesUsage, purgeModuleSamples, recordModuleSamples, UsageTask } from '../../server/usage/samples'
import { buildUsage, lastRuns, requiredBy, scannerStats, serviceSeries, serviceStats } from '../../server/usage/stats'

const DAY = 86_400_000
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z')

function catalogModule(id: string, type: string, extra: Record<string, unknown> = {}) {
  return { id, name: id, type, version: '1.0.0', license: { spdx: 'MIT', restrictions: 'none' }, ...extra }
}
const INDEX_DOC = {
  schema: 1,
  version: 3,
  generated_at: '2026-11-24T08:00:00Z',
  modules: [
    catalogModule('gitleaks', 'scanner'),
    catalogModule('trivy', 'scanner', { needs: { feeds: ['trivy-db'] } }),
    catalogModule('fresh', 'scanner'),
    catalogModule('trivy-db', 'feed'),
    catalogModule('osv-db', 'feed'),
    catalogModule('sonarqube', 'service'),
    catalogModule('sonar-scanner', 'scanner', { requires: { modules: ['sonarqube'] } }),
    catalogModule('defectdojo', 'service'),
  ],
  packs: [],
}

function installed(id: string, type: InstalledModule['type'], installedAt: string | null): InstalledModule {
  return { id, version: '1.0.0', type, status: 'healthy', enabled: true, installed_at: installedAt, options: {}, testbed: null }
}

describe.skipIf(!DATABASE_URL)('consommation des modules (F14, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let projectId: string
  let profileId: string
  let gateId: string
  let n = 0
  const now = Date.now()
  const old = iso(now - 100 * DAY)
  const INSTALLED: InstalledModule[] = [
    installed('gitleaks', 'scanner', old),
    installed('trivy', 'scanner', old),
    installed('fresh', 'scanner', iso(now - DAY)),
    installed('trivy-db', 'feed', old),
    installed('osv-db', 'feed', old),
    installed('sonarqube', 'service', old),
    installed('sonar-scanner', 'scanner', null),
    installed('defectdojo', 'service', old),
  ]

  async function scanWith(finishedAt: number, modules: { id: string, status: string, mem?: number | null, cpu?: number | null, dur?: number | null }[]) {
    const s = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, finished_at)
       VALUES ($1, $2, 'manual', 50, 'main', $3, $4, 'done', $5) RETURNING id`,
      [projectId, ++n, profileId, gateId, new Date(finishedAt)])).rows[0]!.id
    for (const m of modules) {
      await db.pool.query(
        `INSERT INTO scan_modules (scan_id, module_id, module_version, status, peak_memory_mb, cpu_ms, duration_ms, started_at, finished_at)
         VALUES ($1, $2, '1.0.0', $3, $4, $5, $6, $7, $7)`,
        [s, m.id, m.status, m.mem ?? null, m.cpu ?? null, m.dur ?? null, new Date(finishedAt)])
    }
    return s
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-usage-'))
    const ids = (await db.pool.query<{ p: string, g: string }>(
      `SELECT (SELECT id FROM profiles WHERE slug = 'rapide') AS p, (SELECT id FROM gates WHERE slug = 'defaut') AS g`)).rows[0]!
    profileId = ids.p
    gateId = ids.g
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('alpha', 'Alpha', 'archive', $1, $2) RETURNING id`,
      [profileId, gateId])).rows[0]!.id
    // trivy : 5 analyses réussies (mémoire 100…400 avec une mesure absente), 1 échec ; gitleaks : il y a 40 jours.
    const durs = [1000, 2000, 3000, 4000, 5000]
    const mems = [100, 200, null, 300, 400]
    for (let i = 0; i < 5; i++) await scanWith(now - (i + 1) * 3600_000, [{ id: 'trivy', status: 'ok', mem: mems[i], cpu: 1000 * (i + 1), dur: durs[i] }])
    await scanWith(now - 2 * DAY, [{ id: 'trivy', status: 'oom', mem: 2048, dur: 999_999 }, { id: 'fresh', status: 'skipped' }])
    await scanWith(now - 40 * DAY, [{ id: 'gitleaks', status: 'ok', mem: 50, dur: 700 }, { id: 'sonar-scanner', status: 'pending' }])
  })

  afterAll(async () => {
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('statistiques des scanners : médiane et p95, mesures absentes ignorées, échecs comptés', async () => {
    const stats = await scannerStats(db.pool, 30)
    const trivy = stats.get('trivy')!
    expect(trivy.runs).toBe(6)
    expect(trivy.failures).toBe(1)
    expect(trivy.memory_max_mb).toBe(2048)
    // médiane de 100, 200, 300, 400, 2048 (la mesure absente n'est pas un 0)
    expect(trivy.memory_median_mb).toBe(300)
    expect(trivy.cpu_avg_ms).toBe(3000)
    // durées des seules analyses réussies : moyenne 3000, p95 = 1000 + 0,95 × 4000
    expect(trivy.duration_avg_ms).toBe(3000)
    expect(trivy.duration_p95_ms).toBe(4800)
    // gitleaks : hors fenêtre de 30 jours ; skipped et pending ne comptent pas
    expect(stats.has('gitleaks')).toBe(false)
    expect(stats.has('fresh')).toBe(false)
    expect((await scannerStats(db.pool, 30, 'trivy')).size).toBe(1)
    const runs = await lastRuns(db.pool)
    expect(Date.parse(runs.get('gitleaks')!)).toBeLessThan(now - 39 * DAY)
    expect(runs.has('sonar-scanner')).toBe(false)
  })

  it('dépendances : bases et services requis par un module installé (G1)', () => {
    const index = { version: 3, generated_at: null, modules: INDEX_DOC.modules, packs: [], rejected: 0 } as unknown as CatalogIndex
    const deps = requiredBy(INSTALLED, index)
    expect(deps.get('trivy-db')).toEqual(['trivy'])
    expect(deps.get('sonarqube')).toEqual(['sonar-scanner'])
    expect(deps.has('osv-db')).toBe(false)
    expect(requiredBy(INSTALLED, null).size).toBe(0)
  })

  it('modules inutilisés depuis N jours : raisons, jeunes modules et dépendances exclus', async () => {
    const index = { version: 3, generated_at: null, modules: INDEX_DOC.modules, packs: [], rejected: 0 } as unknown as CatalogIndex
    const usage = buildUsage({
      installed: [...INSTALLED, { ...installed('gone', 'scanner', old), status: 'removing' }],
      index,
      scanners: await scannerStats(db.pool),
      services: new Map(),
      lastRuns: await lastRuns(db.pool),
      unusedDays: 30,
      now,
    })
    const by = Object.fromEntries(usage.map(u => [u.id, u]))
    expect(Object.keys(by)).not.toContain('gone')
    expect(by.gitleaks).toMatchObject({ unused: true, unused_reason: 'no-scan', judged: true })
    expect(by.trivy).toMatchObject({ unused: false, judged: true })
    // installé hier : pas encore jugé inutilisé
    expect(by.fresh).toMatchObject({ unused: false, judged: true })
    expect(by.fresh!.scanner!.runs).toBe(0)
    expect(by['osv-db']).toMatchObject({ unused: true, unused_reason: 'no-dependent' })
    expect(by['trivy-db']).toMatchObject({ unused: false, required_by: ['trivy'] })
    expect(by.sonarqube).toMatchObject({ unused: false, judged: true, required_by: ['sonar-scanner'] })
    // jamais lancé, mais date d'installation inconnue : jugé sur ses analyses
    expect(by['sonar-scanner']).toMatchObject({ unused: true, unused_reason: 'no-scan' })
    expect(by.defectdojo).toMatchObject({ unused: false, judged: false, scanner: null, service: null })
    // seuil plus long : gitleaks (40 jours) n'est plus inutilisé
    const longer = buildUsage({ installed: INSTALLED, index, scanners: new Map(), services: new Map(), lastRuns: await lastRuns(db.pool), unusedDays: 60, now })
    expect(longer.find(u => u.id === 'gitleaks')!.unused).toBe(false)
  })

  it('relevés : recopie de l’état sans doublon, entrées invalides écartées, purge à 90 jours', async () => {
    const stateFile = join(root, 'state.json')
    const at = (minAgo: number) => iso(now - minAgo * 60_000)
    await writeFile(stateFile, JSON.stringify({
      version: 1,
      generated_at: iso(now),
      modules_usage: [
        { id: 'sonarqube', usage: { memory_mb: 2048, cpu_pct: null, disk_mb: 900, at: at(1) } },
        { id: 'sonarqube', usage: { memory_mb: 2048, cpu_pct: null, disk_mb: 900, at: at(1) } },
        { id: 'defectdojo', usage: { memory_mb: 0, cpu_pct: 0, disk_mb: 300, at: at(1) } },
        { id: 'BAD', usage: { memory_mb: 1, cpu_pct: 1, disk_mb: 1, at: at(1) } },
        { id: 'sonarqube', usage: { memory_mb: -5, cpu_pct: 1, disk_mb: 1, at: at(2) } },
        { id: 'sonarqube', usage: { memory_mb: 1, at: 'hier' } },
        'nimporte',
      ],
    }))
    expect(parseModulesUsage(null)).toEqual([])
    expect(parseModulesUsage({ modules_usage: 'x' })).toEqual([])
    expect(await recordModuleSamples(db.pool, stateFile, now)).toBe(2)
    expect(await recordModuleSamples(db.pool, stateFile, now)).toBe(0)
    const rows = (await db.pool.query('SELECT module_id, memory_mb, cpu_pct, disk_mb FROM module_samples ORDER BY module_id')).rows
    expect(rows).toEqual([
      { module_id: 'defectdojo', memory_mb: 0, cpu_pct: 0, disk_mb: 300 },
      { module_id: 'sonarqube', memory_mb: 2048, cpu_pct: null, disk_mb: 900 },
    ])
    // état absent ou sans la clé (ancienne appliance) : rien
    expect(await recordModuleSamples(db.pool, join(root, 'absent.json'), now)).toBe(0)

    // relevés anciens : purgés au-delà de 90 jours
    await db.pool.query(`INSERT INTO module_samples (module_id, at, memory_mb) VALUES ('sonarqube', now() - interval '91 days', 1), ('sonarqube', now() - interval '89 days', 1)`)
    expect(await purgeModuleSamples(db.pool)).toBe(1)
    expect(Number((await db.pool.query(`SELECT count(*) FROM module_samples WHERE module_id = 'sonarqube'`)).rows[0].count)).toBe(2)

    // tâche du worker : recopie au plus une fois par période, purge quotidienne, n'échoue jamais
    const logs: string[] = []
    const task = new UsageTask(db.pool, { stateFile, log: m => logs.push(m) })
    await task.iterate(new Date(now))
    await task.iterate(new Date(now + 1000))
    const failing = { query: async () => { throw new Error('base indisponible') } } as never
    const broken = new UsageTask(failing, { stateFile, log: m => logs.push(m) })
    await broken.iterate(new Date(now))
    expect(logs.some(l => l.includes('base indisponible'))).toBe(true)
  })

  it('modules permanents : synthèse et courbes sur 7 et 30 jours', async () => {
    await db.pool.query('DELETE FROM module_samples')
    for (let h = 0; h < 48; h++) {
      await db.pool.query('INSERT INTO module_samples (module_id, at, memory_mb, cpu_pct, disk_mb) VALUES ($1, now() - make_interval(hours => $2), $3, $4, $5)',
        ['sonarqube', h, 1000 + h, h % 2 ? 10 : 30, 500])
    }
    await db.pool.query(`INSERT INTO module_samples (module_id, at, memory_mb, cpu_pct, disk_mb) VALUES ('sonarqube', now() - interval '20 days', 4000, 50, 400)`)
    const s = (await serviceStats(db.pool, 30)).get('sonarqube')!
    expect(s.samples).toBe(49)
    expect(s.memory_max_mb).toBe(4000)
    expect(s.latest).toMatchObject({ memory_mb: 1000, cpu_pct: 30, disk_mb: 500 })
    expect(s.disk_max_mb).toBe(500)
    expect((await serviceStats(db.pool, 30, 'defectdojo')).size).toBe(0)
    const d7 = await serviceSeries(db.pool, 'sonarqube', 7)
    expect(d7.length).toBeGreaterThanOrEqual(48)
    expect(d7.length).toBeLessThanOrEqual(49)
    expect(d7.every(p => p.memory_avg_mb! < 4000)).toBe(true)
    const d30 = await serviceSeries(db.pool, 'sonarqube', 30)
    expect(d30.length).toBeLessThan(d7.length)
    expect(d30[0]!.memory_max_mb).toBe(4000)
    expect(Date.parse(d30[1]!.at) - Date.parse(d30[0]!.at)).toBeGreaterThanOrEqual(4 * 3600_000)
  })

  describe('API /api/usage', () => {
    let server: Server
    let base: string
    let auth = true

    beforeAll(async () => {
      await writeFile(join(root, 'index.json'), JSON.stringify(INDEX_DOC))
      await writeFile(join(root, 'modules.json'), JSON.stringify({ version: 1, updated_at: '2026-11-24T08:00:00Z', operations: [], modules: INSTALLED }))
      setConfig(loadConfig({
        NUXT_DATABASE_URL: db.url,
        NUXT_STATE_FILE: join(root, 'state.json'),
        NUXT_MODULES_STATE_FILE: join(root, 'modules.json'),
        NUXT_CATALOG_INDEX_FILE: join(root, 'index.json'),
      }))
      const app = createApp()
      app.use(defineEventHandler((event) => {
        if (auth) event.context.auth = { user: { id: 1, username: 'v', displayName: null, role: 'viewer', locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
      }))
      const router = createRouter()
      router.get('/api/usage/modules', (await import('../../server/api/usage/modules/index.get')).default as EventHandler)
      router.get('/api/usage/modules/:id', (await import('../../server/api/usage/modules/[id].get')).default as EventHandler)
      app.use(router)
      server = createServer(toNodeListener(app))
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      const addr = server.address()
      base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
    })
    afterAll(async () => {
      if (!server) return
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    })

    const get = async (path: string) => {
      const res = await fetch(`${base}${path}`)
      return { status: res.status, data: await res.json() as Record<string, unknown> & { data?: { code?: string } } }
    }

    it('liste, seuil réglable, détail avec courbes, erreurs et droits', async () => {
      const list = await get('/api/usage/modules')
      expect(list.status).toBe(200)
      expect(list.data).toMatchObject({ window_days: 30, unused_days: 30 })
      expect((list.data.unused as string[]).sort()).toEqual(['gitleaks', 'osv-db', 'sonar-scanner'])
      expect((await get('/api/usage/modules?unused_days=60')).data.unused).toEqual(['osv-db', 'sonar-scanner'])
      expect((await get('/api/usage/modules?unused_days=0')).status).toBe(400)
      expect((await get('/api/usage/modules?other=1')).status).toBe(400)

      const svc = await get('/api/usage/modules/sonarqube')
      expect(svc.status).toBe(200)
      const series = svc.data.series as Record<string, unknown[]>
      expect(series['7']!.length).toBeGreaterThan(0)
      expect(series['30']!.length).toBeGreaterThan(0)
      const scanner = await get('/api/usage/modules/trivy')
      expect(scanner.data).toMatchObject({ series: null, usage: { id: 'trivy', scanner: { runs: 6 } } })
      expect((await get('/api/usage/modules/absent')).status).toBe(404)
      expect((await get('/api/usage/modules/BAD!')).status).toBe(404)
      expect((await get(`/api/usage/modules/${randomUUID().slice(0, 8)}`)).data.data?.code).toBe('E_NOT_FOUND')
      auth = false
      expect((await get('/api/usage/modules')).status).toBe(401)
      expect((await get('/api/usage/modules/trivy')).status).toBe(401)
      auth = true
    })
  })
})
