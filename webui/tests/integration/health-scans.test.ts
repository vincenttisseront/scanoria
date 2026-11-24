// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G20 et I15 contre un vrai PostgreSQL : santé par outil sur 7 et 30 jours
// (échecs par classe, délais, mémoire, sorties invalides, durées), analyses
// en échec récentes, journal téléchargeable (opérateurs seulement, masqué,
// borné, tronqué, audité) et demande de diagnostic IA d'une analyse en échec,
// avec la fin masquée du journal.

import { randomBytes } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp, createRouter, defineEventHandler, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, DATABASE_URL, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { loadWorkerConfig } from '../../server/scans/config'
import { pendingGate, type AiTaskRequest, type Integrations } from '../../server/scans/integrations'
import { ScanWorker } from '../../server/scans/worker'
import { logExcerpt, maskLog, MAX_AI_EXCERPT, MAX_LOG_DOWNLOAD, readModuleLog } from '../../server/health/log'
import { recentFailures, scanHealth, toolHealth } from '../../server/health/scans'

const DAY = 86_400_000
// Faux secrets générés à l'exécution : aucun motif de secret dans le dépôt.
const FAKE_PASSWORD = randomBytes(12).toString('hex')
const FAKE_GH = `gh${'p'}_${randomBytes(24).toString('hex').slice(0, 36)}`
const RANDOM_VALUE = `${randomBytes(18).toString('base64url').replace(/[-_]/g, 'B')}xY7`
const PEM = [`-----BEGIN ${'OPENSSH'} PRIVATE KEY-----`, randomBytes(30).toString('base64'), randomBytes(30).toString('base64'), `-----END ${'OPENSSH'} PRIVATE KEY-----`].join('\n')

describe.skipIf(!DATABASE_URL)('santé des analyses (G20, PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let logsDir: string
  let projectId: string
  let profileId: string
  let gateId: string
  let n = 0
  const now = Date.now()

  async function scanWith(finishedAt: number, modules: { id: string, status: string, cls?: string | null, dur?: number | null, log?: string }[], status = 'done') {
    const s = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, status, finished_at)
       VALUES ($1, $2, 'manual', 50, 'main', $3, $4, $5, $6) RETURNING id`,
      [projectId, ++n, profileId, gateId, status, new Date(finishedAt)])).rows[0]!.id
    for (const m of modules) {
      let logPath: string | null = null
      if (m.log !== undefined) {
        await mkdir(join(logsDir, s), { recursive: true })
        await writeFile(join(logsDir, s, `${m.id}.log`), m.log)
        logPath = `${s}/${m.id}.log`
      }
      await db.pool.query(
        `INSERT INTO scan_modules (scan_id, module_id, module_version, status, error_class, duration_ms, log_path, started_at, finished_at)
         VALUES ($1, $2, '1.0.0', $3, $4, $5, $6, $7, $7)`,
        [s, m.id, m.status, m.cls ?? null, m.dur ?? null, logPath, new Date(finishedAt)])
    }
    return s
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-health-'))
    logsDir = join(root, 'scan-logs')
    await mkdir(logsDir, { recursive: true })
    const ids = (await db.pool.query<{ p: string, g: string }>(
      `SELECT (SELECT id FROM profiles WHERE slug = 'rapide') AS p, (SELECT id FROM gates WHERE slug = 'defaut') AS g`)).rows[0]!
    profileId = ids.p
    gateId = ids.g
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id) VALUES ('alpha', 'Alpha', 'archive', $1, $2) RETURNING id`,
      [profileId, gateId])).rows[0]!.id
  })

  afterAll(async () => {
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  it('santé par outil sur 7 et 30 jours : classes, délais, mémoire, sorties invalides, durées', async () => {
    await scanWith(now - 3600_000, [{ id: 'trivy', status: 'ok', dur: 1000 }, { id: 'gitleaks', status: 'timeout', cls: 'tool', log: 'délai\n' }])
    await scanWith(now - 2 * 3600_000, [{ id: 'trivy', status: 'oom', cls: 'infra', dur: 50_000, log: 'oom\n' }, { id: 'gitleaks', status: 'ok', dur: 3000 }], 'error')
    await scanWith(now - 3 * 3600_000, [{ id: 'trivy', status: 'invalid-output', cls: null }, { id: 'gitleaks', status: 'error', cls: 'input' }])
    await scanWith(now - 10 * DAY, [{ id: 'trivy', status: 'ok', dur: 3000 }, { id: 'gitleaks', status: 'skipped' }])
    await scanWith(now - 40 * DAY, [{ id: 'trivy', status: 'error', cls: 'infra' }])

    const d7 = Object.fromEntries((await toolHealth(db.pool, 7)).map(t => [t.module_id, t]))
    expect(d7.trivy).toMatchObject({
      runs: 3, ok: 1, failures: 2, failure_rate: 0.667, by_class: { infra: 1, tool: 1, input: 0 },
      timeouts: 0, oom: 1, invalid_output: 1, duration_avg_ms: 1000, duration_p95_ms: 1000,
    })
    expect(d7.gitleaks).toMatchObject({ runs: 3, failures: 2, by_class: { infra: 0, tool: 1, input: 1 }, timeouts: 1 })
    expect(d7.gitleaks!.last_failure_at).not.toBeNull()
    const d30 = Object.fromEntries((await toolHealth(db.pool, 30)).map(t => [t.module_id, t]))
    // skipped ne compte pas ; l'échec d'il y a 40 jours est hors fenêtre
    expect(d30.trivy).toMatchObject({ runs: 4, ok: 2, failures: 2, duration_avg_ms: 2000, duration_p95_ms: 2900 })
    expect(d30.gitleaks!.runs).toBe(3)
  })

  it('analyses en échec récentes, avec les modules en échec et la présence du journal', async () => {
    const list = await recentFailures(db.pool)
    expect(list).toHaveLength(3)
    expect(list[0]!.modules).toEqual([{ module_id: 'gitleaks', status: 'timeout', error_class: 'tool', has_log: true }])
    expect(list[1]!).toMatchObject({ project_name: 'Alpha', status: 'error', modules: [{ module_id: 'trivy', status: 'oom', error_class: 'infra', has_log: true }] })
    expect(list[2]!.modules.map(m => m.module_id)).toEqual(['gitleaks', 'trivy'])
    expect(await recentFailures(db.pool, 1)).toHaveLength(1)
    const all = await scanHealth(db.pool)
    expect(Object.keys(all.windows)).toEqual(['7', '30'])
    expect(all.recent_failures).toHaveLength(3)
  })

  it('masquage commun du journal : motifs connus, clé privée sur plusieurs lignes, lignes très longues', () => {
    const raw = [
      'clone https://ci:' + FAKE_PASSWORD + '@forge.exemple.test/a.git',
      `password=${FAKE_PASSWORD}`,
      `token ${FAKE_GH} utilisé`,
      PEM,
      `${'x'.repeat(9000)} ${FAKE_GH}`,
      'fin normale',
    ].join('\n')
    const out = maskLog(raw)
    expect(out).not.toContain(FAKE_PASSWORD)
    expect(out).not.toContain(FAKE_GH)
    for (const line of PEM.split('\n').slice(1, 3)) expect(out).not.toContain(line)
    expect(out).toContain('fin normale')
    expect(out).toContain('forge.exemple.test')
    expect(maskLog('')).toBe('')
    // secret à cheval sur la limite d'un morceau, dans une très longue ligne (JSON minifié)
    for (const pad of [3990, 3995, 3999, 4000, 4005]) {
      const json = `{"a":"${'y'.repeat(pad)}","token":"${FAKE_GH}","password":"${FAKE_PASSWORD}","b":"${'z'.repeat(5000)}"}`
      const masked = maskLog(json)
      expect(masked).not.toContain(FAKE_GH)
      expect(masked).not.toContain(FAKE_PASSWORD)
    }
    // valeur aléatoire sans étiquette : masquée seulement en mode agressif (envoi à l'IA)
    const random = randomBytes(18).toString('base64url').replace(/[-_]/g, 'A') + 'aZ9'
    expect(maskLog(`candidat ${random}`)).toContain(random)
    expect(maskLog(`candidat ${random}`, { aggressive: true })).not.toContain(random)
  })

  it('lecture bornée : troncature signalée, fin de journal, extrait IA ≤ 16 Ko, chemins refusés', async () => {
    const dir = join(logsDir, '00000000-0000-4000-8000-000000000001')
    await mkdir(dir, { recursive: true })
    await writeFile(join(dir, 'big.log'), `${'début\n'.repeat(10)}${'é'.repeat(MAX_LOG_DOWNLOAD)}\nderniere ligne ${FAKE_GH}\n`)
    const rel = '00000000-0000-4000-8000-000000000001/big.log'
    const full = await readModuleLog(logsDir, rel)
    expect(full!.truncated).toBe(true)
    expect(full!.text.startsWith('début')).toBe(true)
    // début et fin : l'erreur finale n'est pas perdue, toujours masquée
    expect(full!.text).toContain('[…]')
    expect(full!.text).toContain('derniere ligne')
    expect(full!.text).not.toContain(FAKE_GH)
    expect(Buffer.byteLength(full!.text)).toBeLessThan(MAX_LOG_DOWNLOAD + 200)
    const tail = await readModuleLog(logsDir, rel, { maxBytes: 100, tail: true })
    expect(tail!.text).toContain('derniere ligne')
    expect(tail!.text).not.toContain(FAKE_GH)
    const excerpt = await logExcerpt(logsDir, rel)
    expect(Buffer.byteLength(excerpt!, 'utf8')).toBeLessThanOrEqual(MAX_AI_EXCERPT)
    expect(excerpt).toContain('derniere ligne')
    await writeFile(join(dir, 'small.log'), 'court\n')
    expect(await readModuleLog(logsDir, '00000000-0000-4000-8000-000000000001/small.log')).toEqual({ text: 'court\n', truncated: false })
    expect(await readModuleLog(logsDir, '../etc/passwd')).toBeNull()
    expect(await readModuleLog(logsDir, null)).toBeNull()
    expect(await readModuleLog(logsDir, '00000000-0000-4000-8000-000000000001/absent.log')).toBeNull()
    expect(await logExcerpt(logsDir, null)).toBeNull()
  })

  it('I15 : diagnostic demandé une fois pour une analyse en échec, avec la fin masquée du journal', async () => {
    const calls: AiTaskRequest[] = []
    const logs: string[] = []
    const integrations: Integrations = {
      decryptSecret: async () => ({ kind: 'token', value: '', username: null }),
      ingestModuleOutputs: async () => ({ count: 0, newCount: 0, errors: [] }),
      finalizeScanFindings: async () => undefined,
      evaluateGate: (pool, scanId) => pendingGate(pool, scanId),
      enqueueAiTask: async (_db, req) => {
        calls.push(req)
        return null
      },
      runProjectSchedules: async () => undefined,
    }
    const cfg = { ...loadWorkerConfig({}), scanLogsDir: logsDir }
    const w = new ScanWorker(db.pool, cfg, { modulesStateFile: join(root, 'm.json'), catalogIndexFile: join(root, 'i.json') }, integrations, m => logs.push(m))

    const failed = await scanWith(now, [
      { id: 'trivy', status: 'oom', cls: 'infra', log: `démarrage\nmot de passe password=${FAKE_PASSWORD}\nkilled\n` },
      { id: 'gitleaks', status: 'ok', log: 'ok\n' },
      { id: 'osv-scanner', status: 'invalid-output', cls: 'tool' },
    ], 'ingesting')
    await writeFile(join(logsDir, failed, 'trivy.log'), `démarrage\nmot de passe password=${FAKE_PASSWORD}\nvaleur ${RANDOM_VALUE}\nkilled\n`)
    await w.conclude(failed, { status: 'done', error: null, complete: false })
    const diag = calls.filter(c => c.kind === 'diagnose-scan')
    expect(diag).toHaveLength(1)
    expect(diag[0]).toMatchObject({ subjectType: 'scan', subjectId: failed, projectId })
    const ctx = diag[0]!.context as { logs: { module: string, excerpt: string }[] }
    // seul trivy a un journal ; osv-scanner (sans journal) n'apporte pas d'extrait
    expect(ctx.logs.map(l => l.module)).toEqual(['trivy'])
    expect(ctx.logs[0]!.excerpt).toContain('killed')
    expect(ctx.logs[0]!.excerpt).not.toContain(FAKE_PASSWORD)
    // extrait IA : mode agressif, une valeur aléatoire sans étiquette ne part pas
    expect(ctx.logs[0]!.excerpt).not.toContain(RANDOM_VALUE)

    // analyse réussie : aucune demande de diagnostic
    calls.length = 0
    const ok = await scanWith(now, [{ id: 'trivy', status: 'ok' }, { id: 'gitleaks', status: 'skipped' }], 'ingesting')
    await w.conclude(ok, { status: 'done', error: null, complete: true })
    expect(calls.map(c => c.kind)).toEqual(['explain-verdict'])

    // l'IA ne fait jamais échouer une analyse
    const broken = new ScanWorker(db.pool, cfg, { modulesStateFile: join(root, 'm.json'), catalogIndexFile: join(root, 'i.json') },
      { ...integrations, enqueueAiTask: async () => { throw new Error('ia indisponible') } }, m => logs.push(m))
    const again = await scanWith(now, [{ id: 'trivy', status: 'timeout', cls: 'tool' }], 'ingesting')
    await broken.conclude(again, { status: 'done', error: null, complete: false })
    expect((await db.pool.query('SELECT status FROM scans WHERE id = $1', [again])).rows[0].status).toBe('done')
    expect(logs.some(l => l.includes('diagnosis not queued'))).toBe(true)
  })

  describe('API', () => {
    let server: Server
    let base: string
    let role: 'viewer' | 'operator' | null = 'operator'
    let scanId: string

    beforeAll(async () => {
      process.env.SCANORIA_SCAN_LOGS_DIR = logsDir
      setConfig(loadConfig({ NUXT_DATABASE_URL: db.url }))
      const app = createApp()
      app.use(defineEventHandler((event) => {
        if (role) event.context.auth = { user: { id: 1, username: 'ops', displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
      }))
      const router = createRouter()
      router.get('/api/health/scans', (await import('../../server/api/health/scans.get')).default as EventHandler)
      router.get('/api/scans/:id/modules/:module/log', (await import('../../server/api/scans/[id]/modules/[module]/log.get')).default as EventHandler)
      app.use(router)
      server = createServer(toNodeListener(app))
      await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
      const addr = server.address()
      base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
      scanId = await scanWith(now, [
        { id: 'trivy', status: 'error', cls: 'tool', log: `erreur\nAuthorization: Bearer ${FAKE_GH}\n` },
        { id: 'gitleaks', status: 'error', cls: 'tool', log: 'x'.repeat(MAX_LOG_DOWNLOAD + 10) },
      ])
    })
    afterAll(async () => {
      delete process.env.SCANORIA_SCAN_LOGS_DIR
      if (!server) return
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    })

    const get = async (path: string) => {
      const res = await fetch(`${base}${path}`)
      const text = await res.text()
      return { status: res.status, text, headers: res.headers }
    }

    it('santé : lecteur autorisé, anonyme refusé', async () => {
      role = 'viewer'
      const r = await get('/api/health/scans')
      expect(r.status).toBe(200)
      expect(JSON.parse(r.text)).toHaveProperty('windows')
      role = null
      expect((await get('/api/health/scans')).status).toBe(401)
    })

    it('journal : opérateur seulement, masqué, tronqué au-delà de la borne, audité', async () => {
      role = 'viewer'
      expect((await get(`/api/scans/${scanId}/modules/trivy/log`)).status).toBe(403)
      role = 'operator'
      const log = await get(`/api/scans/${scanId}/modules/trivy/log`)
      expect(log.status).toBe(200)
      expect(log.text).toContain('erreur')
      expect(log.text).not.toContain(FAKE_GH)
      expect(log.headers.get('content-disposition')).toMatch(/^attachment; filename="scan-/)
      expect(log.headers.get('cache-control')).toBe('no-store')
      const big = await get(`/api/scans/${scanId}/modules/gitleaks/log`)
      expect(big.text).toContain('[journal tronqué')
      expect(Buffer.byteLength(big.text)).toBeLessThan(MAX_LOG_DOWNLOAD + 200)
      expect((await get(`/api/scans/${scanId}/modules/absent/log`)).status).toBe(404)
      expect((await get(`/api/scans/${scanId}/modules/Bad!/log`)).status).toBe(404)
      expect((await get('/api/scans/pas-un-uuid/modules/trivy/log')).status).toBe(404)
      const audit = await db.pool.query<{ action: string, details: { module: string, truncated: boolean } }>(
        `SELECT action, details FROM audit_log WHERE action = 'scan.log-download' ORDER BY id`)
      expect(audit.rows.map(r => [r.details.module, r.details.truncated])).toEqual([['trivy', false], ['gitleaks', true]])
    })
  })
})
