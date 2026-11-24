// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.5 (B) contre un vrai PostgreSQL 16 : recherche transverse (F3) et droits,
// export CSV, politique de licences (F8, admin seulement, audit, surcharge par
// projet), dates de publication (H5 : demandes au helper, application,
// couverture), re-corrélation (contrat 16 : une par base et par jour, sans
// clone, projets nouvellement touchés signalés).

import { randomBytes } from 'node:crypto'
import { readdirSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, toNodeListener, type EventHandler } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { startConsole, stopConsole, waitReady } from '../../server/utils/runtime'
import { createUser } from '../../server/utils/users'
import { applyDateResults, awaitPackageDates, batches, datesFromOutput, packageDatesTick, DATES_GAP_KIND } from '../../server/sbom/dates'
import { enqueueRecorrelation, feedsToRecorrelate, recorrelationSource, reportRecorrelation, REF_PREFIX } from '../../server/scans/recorrelate'
import { evaluateGate } from '../../server/gates/evaluate'

const API_DIR = fileURLToPath(new URL('../../server/api', import.meta.url))

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

describe.skipIf(!DATABASE_URL)('composants, licences, dates et re-corrélation (PostgreSQL réel)', () => {
  let db: TestDatabase
  let root: string
  let server: Server
  let base: string
  let admin: Client
  let viewer: Client
  let gateId: string
  let profileId: string
  const p = {} as Record<'alpha' | 'beta' | 'gamma', string>
  const s = {} as Record<'alphaOld' | 'alpha' | 'beta' | 'gamma', string>
  let ip = 10

  async function call(path: string, init: RequestInit & { client?: Client, json?: unknown } = {}) {
    const headers = new Headers(init.headers)
    if (init.client) {
      headers.set('cookie', init.client.cookie)
      if (init.method && init.method !== 'GET') headers.set('x-csrf-token', init.client.csrf)
    }
    headers.set('x-real-ip', '192.0.2.20')
    let body = init.body
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json')
      body = JSON.stringify(init.json)
    }
    const res = await fetch(`${base}${path}`, { ...init, headers, body })
    const text = await res.text()
    let data: unknown = text
    try {
      data = JSON.parse(text)
    }
    catch {
      // CSV
    }
    return { status: res.status, headers: res.headers, text, data: data as Json }
  }

  async function login(username: string, role: 'viewer' | 'operator' | 'admin'): Promise<Client> {
    const password = `${username}-long-password`
    await createUser(db.pool, { username, role, password, mustChangePassword: false })
    const res = await fetch(`${base}/api/auth/login`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'x-real-ip': `198.51.100.${ip++}` }, body: JSON.stringify({ username, password }),
    })
    expect(res.status).toBe(200)
    const data = await res.json() as Json
    return { cookie: (res.headers.get('set-cookie') ?? '').split(';')[0]!, csrf: String(data.csrf) }
  }

  async function newProject(slug: string, archived = false): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, default_branch, archived_at)
       VALUES ($1, $2, 'archive', $3, $4, 'main', $5) RETURNING id`, [slug, `Projet ${slug}`, profileId, gateId, archived ? new Date() : null])
    return r.rows[0]!.id
  }

  async function newScan(projectId: string, o: { status?: string, trigger?: string, ref?: string, sbom_source?: string } = {}): Promise<string> {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, finished_at, sbom_source)
       VALUES ($1, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, $2, 50, $3, $4, $5, $6, $7,
               CASE WHEN $7 = 'done' THEN now() END, $8) RETURNING id`,
      [projectId, o.trigger ?? 'manual', o.ref ?? 'main', 'a'.repeat(40), profileId, gateId, o.status ?? 'done', o.sbom_source ?? null])
    return r.rows[0]!.id
  }

  async function component(scanId: string, projectId: string, purl: string, licenses: string[] = ['MIT'], published?: string) {
    const m = /^pkg:([^/]+)\/(.+)@([^?#]+)/.exec(purl)!
    await db.pool.query(
      `INSERT INTO sbom_components (scan_id, project_id, purl, ecosystem, name, version, licenses, direct, published_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8)`,
      [scanId, projectId, purl, m[1], decodeURIComponent(m[2]!), m[3], licenses, published ?? null])
  }

  async function finding(projectId: string, o: { vuln_ids: string[], name: string, version: string, severity?: string, first_scan_id?: string, status?: string }) {
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, vuln_ids, package, status, first_scan_id)
       VALUES ($1, $2, 'osv-scanner', $3, 'sca', $4, 't', 'package-lock.json', $5, $6, $7, $8) RETURNING id`,
      [projectId, randomBytes(32).toString('hex'), o.vuln_ids[0], o.severity ?? 'high', o.vuln_ids,
        JSON.stringify({ ecosystem: 'npm', name: o.name, version: o.version }), o.status ?? 'new', o.first_scan_id ?? null])
    return r.rows[0]!.id
  }

  const requestFiles = async () => (await readdir(join(root, 'requests', 'incoming'))).filter(f => f.endsWith('.json'))

  beforeAll(async () => {
    db = await createTestDatabase()
    root = await mkdtemp(join(tmpdir(), 'scanoria-components-'))
    for (const d of ['requests/tmp', 'requests/incoming', 'requests/done', 'requests/failed', 'bootstrap']) {
      await mkdir(join(root, d), { recursive: true, mode: 0o700 })
    }
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: join(root, 'requests'),
      NUXT_BOOTSTRAP_DIR: join(root, 'bootstrap'),
      NUXT_STATE_FILE: join(root, 'state.json'),
      NUXT_VERSION_FILE: join(root, 'VERSION'),
      NUXT_MIGRATE_ON_START: '0',
      NUXT_INGEST_INTERVAL_MS: '600000',
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
    profileId = (await db.pool.query<{ id: string }>('SELECT id FROM profiles WHERE slug = \'rapide\'')).rows[0]!.id
    admin = await login('cadmin', 'admin')
    viewer = await login('cviewer', 'viewer')

    // alpha : ancienne analyse (minimist 1.2.5) puis dernière analyse (minimist 1.2.8).
    p.alpha = await newProject('alpha')
    s.alphaOld = await newScan(p.alpha)
    await component(s.alphaOld, p.alpha, 'pkg:npm/minimist@1.2.5')
    await db.pool.query(`UPDATE scans SET finished_at = now() - interval '2 days' WHERE id = $1`, [s.alphaOld])
    s.alpha = await newScan(p.alpha)
    await component(s.alpha, p.alpha, 'pkg:npm/minimist@1.2.8')
    await component(s.alpha, p.alpha, 'pkg:npm/%40exemple/outil@2.0.0', ['GPL-3.0-only'])
    // beta : minimist vulnérable, vu par un résultat ouvert sous un alias GHSA.
    p.beta = await newProject('beta')
    s.beta = await newScan(p.beta)
    await component(s.beta, p.beta, 'pkg:npm/minimist@1.2.5', ['MIT'])
    await component(s.beta, p.beta, 'pkg:pypi/requests@2.31.0', ['Apache-2.0'])
    await finding(p.beta, { vuln_ids: ['GHSA-xvch-5gv4-984h'], name: 'minimist', version: '1.2.5', severity: 'critical' })
    await db.pool.query(`INSERT INTO vuln_intel (vuln_id, aliases, kev) VALUES ('CVE-2021-44906', '{GHSA-xvch-5gv4-984h}', false)`)
    // gamma : archivé, visible des administrateurs seulement.
    p.gamma = await newProject('gamma', true)
    s.gamma = await newScan(p.gamma)
    await component(s.gamma, p.gamma, 'pkg:npm/minimist@1.2.6')
  })

  afterAll(async () => {
    await new Promise(resolve => server?.close(resolve))
    stopConsole()
    await closePool()
    await db?.drop()
    if (root) await rm(root, { recursive: true, force: true })
  })

  describe('recherche transverse (F3)', () => {
    it('authentification exigée, paramètres validés', async () => {
      expect((await call('/api/components?name=minimist')).status).toBe(401)
      expect((await call('/api/components', { client: viewer })).status).toBe(400)
      expect((await call('/api/components?name=x&limit=1000', { client: viewer })).status).toBe(400)
    })

    it('dernier SBOM de chaque projet ; archivé masqué pour un lecteur', async () => {
      const r = await call('/api/components?name=minimist', { client: viewer })
      expect(r.status).toBe(200)
      expect(r.data.items.map((i: Json) => i.project.slug)).toEqual(['alpha', 'beta'])
      expect(r.data.items[0].components.map((c: Json) => c.version)).toEqual(['1.2.8'])
      expect(r.data.items[0].scan.id).toBe(s.alpha)
      const a = await call('/api/components?name=minimist', { client: admin })
      expect(a.data.items.map((i: Json) => i.project.slug)).toEqual(['alpha', 'beta', 'gamma'])
      expect(a.data.items[2].project.archived).toBe(true)
    })

    it('purl exact ou par préfixe, écosystème, intervalle de versions', async () => {
      const exact = await call(`/api/components?purl=${encodeURIComponent('pkg:npm/minimist@1.2.5')}`, { client: viewer })
      expect(exact.data.items.map((i: Json) => i.project.slug)).toEqual(['beta'])
      const prefix = await call(`/api/components?purl=${encodeURIComponent('pkg:npm/minimist')}`, { client: viewer })
      expect(prefix.data.total_components).toBe(2)
      const range = await call('/api/components?name=minimist&version_from=1.0.0&version_to=1.2.6', { client: admin })
      expect(range.data.items.map((i: Json) => i.project.slug)).toEqual(['beta', 'gamma'])
      const eco = await call('/api/components?name=requests&ecosystem=npm', { client: viewer })
      expect(eco.data.total_components).toBe(0)
    })

    it('par avis, alias compris ; résultats liés joints', async () => {
      for (const vuln of ['CVE-2021-44906', 'GHSA-xvch-5gv4-984h', 'cve-2021-44906']) {
        const r = await call(`/api/components?vuln=${vuln}`, { client: viewer })
        expect(r.data.items.map((i: Json) => i.project.slug), vuln).toEqual(['beta'])
        expect(r.data.items[0].components[0].findings[0]).toMatchObject({ severity: 'critical', vuln_ids: ['GHSA-xvch-5gv4-984h'] })
      }
    })

    it('pagination par projet avec curseur', async () => {
      const first = await call('/api/components?name=minimist&limit=1', { client: admin })
      expect(first.data.items.map((i: Json) => i.project.slug)).toEqual(['alpha'])
      expect(first.data.total_projects).toBe(3)
      const second = await call(`/api/components?name=minimist&limit=1&cursor=${first.data.next_cursor}`, { client: admin })
      expect(second.data.items.map((i: Json) => i.project.slug)).toEqual(['beta'])
      const third = await call(`/api/components?name=minimist&limit=2&cursor=${second.data.next_cursor}`, { client: admin })
      expect(third.data.items.map((i: Json) => i.project.slug)).toEqual(['gamma'])
      expect(third.data.next_cursor).toBeNull()
    })

    it('export CSV : en-tête, une ligne par composant, droits respectés', async () => {
      const r = await call('/api/components/export.csv?name=minimist', { client: viewer })
      expect(r.status).toBe(200)
      expect(r.headers.get('content-type')).toMatch(/text\/csv/)
      expect(r.headers.get('content-disposition')).toMatch(/attachment/)
      const lines = r.text.trim().split(/\r?\n/)
      expect(lines[0]).toBe('project,scan,purl,ecosystem,name,version,licenses,direct,published_at,vulnerabilities')
      expect(lines).toHaveLength(3)
      expect(r.text).not.toContain('gamma')
      expect(r.text).toContain('GHSA-xvch-5gv4-984h')
    })
  })

  describe('politique de licences (F8)', () => {
    it('lecture pour tous, écriture réservée aux administrateurs', async () => {
      const r = await call('/api/licenses/policy', { client: viewer })
      expect(r.status).toBe(200)
      expect(r.data.defaults.allowed).toContain('MIT')
      expect(r.data.global).toEqual([])
      const denied = await call('/api/licenses/policy', { method: 'PUT', client: viewer, json: { project_id: null, license: 'GPL-3.0-only', decision: 'denied' } })
      expect(denied.status).toBe(403)
    })

    it('décision globale puis surcharge du projet, tracées dans l’audit', async () => {
      const g = await call('/api/licenses/policy', { method: 'PUT', client: admin, json: { project_id: null, license: 'GPL-3.0-only', decision: 'denied', reason: 'copyleft fort' } })
      expect(g.status).toBe(200)
      let ev = await call('/api/licenses/evaluate', { method: 'POST', client: viewer, json: { expression: 'MIT AND GPL-3.0-only', project_id: p.alpha } })
      expect(ev.data).toMatchObject({ decision: 'denied', source: 'global' })

      const o = await call('/api/licenses/policy', { method: 'PUT', client: admin, json: { project_id: p.alpha, license: 'gpl-3.0-only', decision: 'allowed', reason: 'outil interne' } })
      expect(o.status).toBe(200)
      ev = await call('/api/licenses/evaluate', { method: 'POST', client: viewer, json: { expression: 'MIT AND GPL-3.0-only', project_id: p.alpha } })
      expect(ev.data).toMatchObject({ decision: 'allowed', source: 'project' })
      ev = await call('/api/licenses/evaluate', { method: 'POST', client: viewer, json: { expression: 'GPL-3.0-only', project_id: p.beta } })
      expect(ev.data.decision).toBe('denied')

      // Même licence, même portée : mise à jour (ancienne valeur dans l'audit).
      const again = await call('/api/licenses/policy', { method: 'PUT', client: admin, json: { project_id: null, license: 'GPL-3.0-only', decision: 'review' } })
      expect(again.data.id).toBe(g.data.id)
      const audit = await db.pool.query<{ action: string, details: Json }>(
        `SELECT action, details FROM audit_log WHERE action LIKE 'license-policy.%' ORDER BY id`)
      expect(audit.rows.map(a => a.action)).toEqual(['license-policy.set', 'license-policy.set', 'license-policy.set'])
      expect(audit.rows[2]!.details).toMatchObject({ decision: 'review', previous: 'denied' })

      const list = await call(`/api/licenses/policy?project_id=${p.alpha}`, { client: viewer })
      expect(list.data.project.map((r: Json) => r.license)).toEqual(['gpl-3.0-only'])
      expect(list.data.projects_with_overrides).toEqual([expect.objectContaining({ slug: 'alpha', count: 1 })])

      await call('/api/licenses/policy', { method: 'PUT', client: admin, json: { project_id: null, license: 'GPL-3.0-only', decision: 'denied' } })
    })

    it('décisions par composant d’une analyse et gate de l’analyse', async () => {
      const r = await call(`/api/licenses/scans/${s.beta}`, { client: viewer })
      expect(r.data.counts).toEqual({ allowed: 2, review: 0, denied: 0 })
      const gp = await newProject('licdenied')
      const sc = await newScan(gp, { status: 'ingesting' })
      await component(sc, gp, 'pkg:npm/copyleft@1.0.0', ['GPL-3.0-only'])
      await component(sc, gp, 'pkg:npm/inconnu@1.0.0', [])
      const lic = await call(`/api/licenses/scans/${sc}`, { client: viewer })
      expect(lic.data.counts).toEqual({ allowed: 0, review: 1, denied: 1 })
      const v = await evaluateGate(db.pool, sc)
      expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'license-denied', blocking: true, count: 1 }))
      expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'license-review', blocking: false, count: 1 }))
    })

    it('retrait audité ; identifiant inconnu → 404', async () => {
      const list = await call(`/api/licenses/policy?project_id=${p.alpha}`, { client: admin })
      const id = list.data.project[0].id
      expect((await call(`/api/licenses/policy/${id}`, { method: 'DELETE', client: viewer })).status).toBe(403)
      expect((await call(`/api/licenses/policy/${id}`, { method: 'DELETE', client: admin })).status).toBe(200)
      expect((await call(`/api/licenses/policy/${id}`, { method: 'DELETE', client: admin })).status).toBe(404)
      const a = await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'license-policy.delete'`)
      expect(a.rowCount).toBe(1)
    })
  })

  describe('dates de publication (H5)', () => {
    it('lots bornés, sortie du helper filtrée', () => {
      const many = Array.from({ length: 4500 }, (_, i) => `pkg:npm/p${i}@1.0.0`)
      expect(batches(many).map(b => b.length)).toEqual([2000, 2000, 500])
      const long = Array.from({ length: 200 }, (_, i) => `pkg:npm/${'x'.repeat(900)}${i}@1.0.0`)
      expect(batches(long).every(b => b.join('","').length < 110 * 1024)).toBe(true)
      const d = datesFromOutput({ dates: { 'pkg:npm/a@1': '2026-11-20T08:00:00Z', 'pkg:npm/b@1': null, 'pkg:npm/c@1': 'hier', 'x': '2026-11-20T08:00:00Z' } })
      expect([...d]).toEqual([['pkg:npm/a@1', '2026-11-20T08:00:00Z'], ['pkg:npm/b@1', null]])
      expect(datesFromOutput(null).size).toBe(0)
    })

    it('demandes déposées une fois, dates appliquées, couverture renseignée, gate en quarantaine', async () => {
      const dp = await newProject('dates')
      const known = await newScan(dp)
      await component(known, dp, 'pkg:npm/ancien@1.0.0', ['MIT'], '2024-01-01T00:00:00Z')
      const sc = await newScan(dp, { status: 'ingesting', trigger: 'release', ref: 'v1.0.0' })
      await component(sc, dp, 'pkg:npm/ancien@1.0.0')
      await component(sc, dp, 'pkg:npm/recent@2.0.0')
      await component(sc, dp, 'pkg:npm/introuvable@1.0.0')
      await component(sc, dp, 'pkg:deb/debian/libc6@2.36-9', ['LGPL-2.1-only'])
      expect(await awaitPackageDates(db.pool, sc, { timeoutMs: 50, pollMs: 10 })).toBe(false)

      const before = (await requestFiles()).length
      await packageDatesTick(db.pool, join(root, 'requests'))
      await packageDatesTick(db.pool, join(root, 'requests'))
      const reqs = await db.pool.query<{ id: string, params: Json, file_name: string }>(
        `SELECT id, params, file_name FROM helper_requests WHERE type = 'package-dates' AND params ->> 'scan_id' = $1`, [sc])
      expect(reqs.rowCount).toBe(1)
      expect(reqs.rows[0]!.params.purls).toEqual(['pkg:npm/introuvable@1.0.0', 'pkg:npm/recent@2.0.0'])
      // Un fichier par demande (les autres analyses récentes sont aussi datées), aucun doublon.
      const all = await db.pool.query(`SELECT 1 FROM helper_requests WHERE type = 'package-dates'`)
      expect((await requestFiles()).length).toBe(before + (all.rowCount ?? 0))
      const file = JSON.parse(await readFile(join(root, 'requests', 'incoming', reqs.rows[0]!.file_name), 'utf8'))
      expect(file).toMatchObject({ type: 'package-dates', requested_by: { user_id: 0, username: 'system' } })
      expect(file.params).toEqual({ purls: ['pkg:npm/introuvable@1.0.0', 'pkg:npm/recent@2.0.0'] })
      const copied = await db.pool.query(`SELECT published_at FROM sbom_components WHERE scan_id = $1 AND purl = 'pkg:npm/ancien@1.0.0'`, [sc])
      expect(copied.rows[0]!.published_at).not.toBeNull()

      await db.pool.query(
        `UPDATE helper_requests SET status = 'ok', code = 'OK', finished_at = now(), output = $2 WHERE id = $1`,
        [reqs.rows[0]!.id, JSON.stringify({ dates: { 'pkg:npm/recent@2.0.0': new Date(Date.now() - 2 * 86_400_000).toISOString().replace(/\.\d+Z$/, 'Z'), 'pkg:npm/introuvable@1.0.0': null }, stats: { offline: false } })])
      expect(await applyDateResults(db.pool)).toBe(1)
      expect(await applyDateResults(db.pool)).toBe(0)
      expect(await awaitPackageDates(db.pool, sc, { timeoutMs: 50, pollMs: 10 })).toBe(true)
      const cov = await db.pool.query<{ coverage: Json }>('SELECT coverage FROM scans WHERE id = $1', [sc])
      expect(cov.rows[0]!.coverage.gaps).toContainEqual({ kind: DATES_GAP_KIND, count: 1, offline: false })

      const v = await evaluateGate(db.pool, sc)
      expect(v.reasons).toContainEqual(expect.objectContaining({ code: 'quarantine', blocking: true, count: 1, actions: ['wait'] }))
      expect(v.verdict).toBe('failed')
    })
  })

  describe('re-corrélation (contrat 16)', () => {
    const DAY = 86_400_000
    const t0 = new Date('2026-11-24T06:00:00Z')

    it('au plus une par base et par jour ; première vue = simple marque', () => {
      const feeds = (at: string) => [{ id: 'osv-db', updated_at: at, status: 'ok' }, { id: 'autre', updated_at: at, status: 'ok' }]
      let r = feedsToRecorrelate(feeds('2026-11-24T05:00:00Z'), {}, t0)
      expect(r.due).toEqual([])
      expect(Object.keys(r.marks)).toEqual(['osv-db'])
      r = feedsToRecorrelate(feeds('2026-11-24T07:00:00Z'), r.marks, new Date(t0.getTime() + 3600_000))
      expect(r.due).toEqual(['osv-db'])
      const again = feedsToRecorrelate(feeds('2026-11-24T12:00:00Z'), r.marks, new Date(t0.getTime() + 8 * 3600_000))
      expect(again.due).toEqual([])
      const nextDay = feedsToRecorrelate(feeds('2026-11-25T08:00:00Z'), r.marks, new Date(t0.getTime() + DAY + 3 * 3600_000))
      expect(nextDay.due).toEqual(['osv-db'])
      expect(feedsToRecorrelate([{ id: 'osv-db', updated_at: '2026-11-30T00:00:00Z', status: 'missing' }], r.marks, new Date(t0.getTime() + 10 * DAY)).due).toEqual([])
    })

    it('mise en file unique, sans clone : la source est le SBOM, réf « sbom: »', async () => {
      const id = await enqueueRecorrelation(db.pool, { projectId: p.beta, sourceScanId: s.beta })
      expect(id).toBeTruthy()
      expect(await enqueueRecorrelation(db.pool, { projectId: p.beta, sourceScanId: s.beta })).toBeNull()
      expect(await enqueueRecorrelation(db.pool, { projectId: p.gamma, sourceScanId: s.gamma })).toBeNull()
      const row = await db.pool.query<Json>('SELECT trigger, priority, ref, sbom_source::text, status FROM scans WHERE id = $1', [id])
      expect(row.rows[0]).toMatchObject({ trigger: 'recorrelate', priority: 5, ref: `${REF_PREFIX}main`, sbom_source: s.beta, status: 'queued' })
      const src = await recorrelationSource(db.pool, id!)
      expect(src).toEqual({ kind: 'sbom', scan_id: s.beta, components: ['pkg:npm/minimist@1.2.5', 'pkg:pypi/requests@2.31.0'] })
      expect(src).not.toHaveProperty('url')
      expect(await recorrelationSource(db.pool, s.beta)).toBeNull()
    })

    it('projets nouvellement touchés signalés (audit, bandeau) ; résultat déjà connu ignoré', async () => {
      const rc = (await db.pool.query<{ id: string }>(`SELECT id FROM scans WHERE project_id = $1 AND trigger = 'recorrelate'`, [p.beta])).rows[0]!.id
      const known = await finding(p.beta, { vuln_ids: ['GHSA-xvch-5gv4-984h'], name: 'minimist', version: '1.2.5', severity: 'critical', first_scan_id: rc })
      const fresh = await finding(p.beta, { vuln_ids: ['MAL-2026-0001'], name: 'requests', version: '2.31.0', severity: 'low', first_scan_id: rc })
      const minor = await finding(p.beta, { vuln_ids: ['CVE-2026-0002'], name: 'requests', version: '2.31.0', severity: 'medium', first_scan_id: rc })
      await db.pool.query(`INSERT INTO scan_findings (scan_id, finding_id, is_new) SELECT $1, unnest($2::uuid[]), true`, [rc, [known, fresh, minor]])
      expect(await reportRecorrelation(db.pool, s.beta)).toBe(0)
      expect(await reportRecorrelation(db.pool, rc)).toBe(1)
      const a = await db.pool.query<{ target_id: string, details: Json }>(`SELECT target_id, details FROM audit_log WHERE action = 'recorrelation.exposure'`)
      expect(a.rows).toHaveLength(1)
      expect(a.rows[0]!.target_id).toBe(p.beta)
      expect(a.rows[0]!.details).toMatchObject({ scan_id: rc, count: 1, malicious: 1, finding_ids: [fresh] })
      const banner = await call('/api/components/exposures', { client: viewer })
      expect(banner.data.items).toEqual([expect.objectContaining({ project: expect.objectContaining({ slug: 'beta' }), malicious: 1, count: 1 })])
    })

    it('une re-corrélation ne donne pas de verdict de release concluant', async () => {
      const rc = (await db.pool.query<{ id: string }>(`SELECT id FROM scans WHERE project_id = $1 AND trigger = 'recorrelate'`, [p.beta])).rows[0]!.id
      const v = await evaluateGate(db.pool, rc)
      // Composants lus dans le SBOM d'origine : pas de quarantaine bloquante (pas une release).
      expect(v.reasons.find(r => r.code === 'quarantine')?.blocking ?? false).toBe(false)
    })
  })
})
