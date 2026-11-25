// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier A de la 0.8 (CLAUDE.md § 7) contre PostgreSQL, le vrai helper
// (mode test, file de demandes) et une fausse forge en écriture :
// mode tiré (tag détecté une fois, premier passage limité, tag déplacé
// signalé), rapport canonique, signature par le helper revérifiée par la
// console, statut scanoria/release-gate, fichiers joints à la release
// (droit manquant signalé), contrat 40 émis une fois, comparaison F2 avec la
// release précédente, routes (page, comparaison, téléchargements, clé
// publique, mode poussé) et vérification de l'enveloppe par scanoria-verify.

import { execFileSync, spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer, type Server } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp, createRouter, defineEventHandler, getHeader, toNodeListener } from 'h3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { addRepo, startFakePrForge, type FakePrForge, type FakeRepoState } from '../helpers/fake-pr-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { createUser } from '../../server/utils/users'
import { IngestMemory, ingestResults } from '../../server/utils/ingest'
import { setForgeRetryDelays } from '../../server/forges/http'
import { createForge } from '../../server/projects/forges'
import { discoverForge } from '../../server/projects/discover'
import { getForge } from '../../server/forges'
import { setConsoleUrl } from '../../server/forges/context'
import { pollReleases, resetReleasePolling } from '../../server/release/poll'
import { releaseTick } from '../../server/release/tick'
import { applianceKey, expireStaleReports } from '../../server/release/sign'
import { clearReleaseVerdictListeners, onReleaseVerdict, type ReleaseVerdictEvent } from '../../server/release/events'
import { canonicalBytes, sha256Hex } from '../../server/release/canonical'
import type { Role } from '#shared/schemas'

import viewRoute from '../../server/api/releases/[scanId]/index.get'
import compareRoute from '../../server/api/releases/[scanId]/compare.get'
import fileRoute from '../../server/api/releases/[scanId]/[file].get'
import listRoute from '../../server/api/releases/index.get'
import clientRoute from '../../server/api/releases/client.get'
import keyRoute from '../../server/api/system/appliance-key.get'
import pushRoute from '../../server/api/projects/[id]/releases.post'

const HOST = 'forge.exemple.test'
const CONSOLE = 'https://analyse.exemple.test'
const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url))
const HELPER = join(REPO_ROOT, 'src/rootfs/usr/sbin/scanoria-helper')
const VERIFY = join(REPO_ROOT, 'src/rootfs/usr/share/scanoria/client/scanoria-verify')
const hasTools = spawnSync('openssl', ['version']).status === 0 && spawnSync('python3', ['--version']).status === 0
const sha = () => randomBytes(20).toString('hex')

describe.skipIf(!DATABASE_URL || !hasTools)('gate de release (chantier A, PostgreSQL et helper réels)', () => {
  let db: TestDatabase
  let dir: string
  let testRoot: string
  let requestsDir: string
  let fake: FakePrForge
  let repo: FakeRepoState
  let projectId: string
  let server: Server
  let base: string
  const events: ReleaseVerdictEvent[] = []
  const memory = new IngestMemory()
  const users: Record<Role, number> = { viewer: 0, operator: 0, admin: 0 }

  async function call(path: string, role: Role | null, init: { method?: string, json?: unknown } = {}) {
    const headers: Record<string, string> = {}
    if (role) headers['x-test-role'] = role
    if (init.json !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${base}${path}`, { method: init.method ?? 'GET', headers, body: init.json === undefined ? undefined : JSON.stringify(init.json) })
    const buf = Buffer.from(await res.arrayBuffer())
    let data: Record<string, unknown> = {}
    try {
      data = JSON.parse(buf.toString('utf8'))
    }
    catch {
      // corps non JSON
    }
    const code = (data.data as { code?: string } | undefined)?.code
    return { status: res.status, data, code, buf, headers: res.headers }
  }

  /** Le helper traite la file, puis la console ingère les résultats et fait une passe de release. */
  async function helperRound() {
    execFileSync(HELPER, ['run'], { env: { ...process.env, SCANORIA_TEST_ROOT: testRoot, SCANORIA_TEST_BIN: join(dir, 'stubs'), PYTHONDONTWRITEBYTECODE: '1' }, stdio: 'pipe' })
    await ingestResults(db.pool, requestsDir, memory)
    await releaseTick(db.pool, requestsDir, () => {})
  }

  /** Fin d'analyse simulée : verdict, commit, résultats. */
  async function finishScan(scanId: string, verdict: 'passed' | 'failed', findings: { fp: string, severity: string, tool?: string }[]) {
    await db.pool.query(
      `UPDATE scans SET status = 'done', verdict = $2, verdict_details = '{"reasons": []}'::jsonb, finished_at = now(), started_at = now(),
              commit_sha = COALESCE(commit_sha, (SELECT commit_sha FROM release_candidates WHERE scan_id = $1)) WHERE id = $1`, [scanId, verdict])
    for (const f of findings) {
      const r = await db.pool.query<{ id: string }>(
        `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, status)
         VALUES ($1, $2, $3, 'R-' || $4, 'sca', $4, 'Composant vulnérable', 'package-lock.json', 'new')
         ON CONFLICT (project_id, fingerprint) DO UPDATE SET title = EXCLUDED.title RETURNING id`,
        [projectId, f.fp, f.tool ?? 'osv-scanner', f.severity])
      await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true) ON CONFLICT DO NOTHING', [scanId, r.rows[0]!.id])
    }
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-release-'))
    testRoot = join(dir, 'root')
    requestsDir = join(testRoot, 'var/lib/scanoria/requests')
    for (const d of ['tmp', 'incoming', 'work', 'done', 'failed']) await mkdir(join(requestsDir, d), { recursive: true })
    await chmod(join(requestsDir, 'incoming'), 0o700)
    await chmod(join(requestsDir, 'work'), 0o700)
    await mkdir(join(testRoot, 'run/scanoria'), { recursive: true })
    await mkdir(join(testRoot, 'etc/scanoria'), { recursive: true })
    await mkdir(join(dir, 'stubs'), { recursive: true })
    await writeFile(join(dir, 'stubs/scanoria-state'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    process.env.NUXT_RELEASES_DIR = join(dir, 'releases')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: requestsDir,
      NUXT_OFFLINE_STATUS_FILE: join(testRoot, 'var/lib/scanoria/offline/status.json'),
      NUXT_STATE_FILE: join(testRoot, 'run/scanoria/state.json'),
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    process.env.NUXT_SCANORIA_VERIFY_CLIENT = VERIFY
    setConsoleUrl(CONSOLE)
    setForgeRetryDelays([1, 1])
    for (const role of ['viewer', 'operator', 'admin'] as const) {
      users[role] = Number((await createUser(db.pool, { username: role, role, password: `${role}-long-password` })).id)
    }
    fake = await startFakePrForge(HOST)
    repo = addRepo(fake, 'equipe/app')
    repo.tags = [{ name: 'v0.9.0', sha: sha() }, { name: 'v1.0.0', sha: sha() }, { name: 'docs', sha: sha() }]
    repo.releases = [{ id: 1, tag_name: 'v1.0.0', prerelease: false, assets: [] }]
    const res = await createForge(db.pool, { kind: 'forgejo', name: 'Forge', base_url: `https://${HOST}`, token: fake.token, discovery: true }, { type: 'system' })
    projectId = (await discoverForge(db.pool, (await getForge(db.pool, res.forge.id))!)).created[0]!
    onReleaseVerdict((_db, e) => {
      events.push(e)
    })

    const app = createApp()
    app.use(defineEventHandler((event) => {
      const role = getHeader(event, 'x-test-role') as Role | undefined
      if (role) event.context.auth = { user: { id: users[role], username: role, displayName: null, role, locale: 'fr', mustChangePassword: false }, tokenHash: 'x', csrf: 'x' }
    }))
    const router = createRouter()
    router.get('/api/releases', listRoute)
    router.get('/api/releases/client', clientRoute)
    router.get('/api/releases/:scanId', viewRoute)
    router.get('/api/releases/:scanId/compare', compareRoute)
    router.get('/api/releases/:scanId/:file', fileRoute)
    router.get('/api/system/appliance-key', keyRoute)
    router.post('/api/projects/:id/releases', pushRoute)
    app.use(router)
    server = createServer(toNodeListener(app))
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const addr = server.address()
    base = `http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}`
  })

  afterAll(async () => {
    clearReleaseVerdictListeners()
    resetReleasePolling()
    setConsoleUrl()
    setForgeRetryDelays()
    if (server) await new Promise(resolve => server.close(resolve))
    await fake?.close()
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    delete process.env.NUXT_RELEASES_DIR
    delete process.env.NUXT_SCANORIA_VERIFY_CLIENT
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  let first: string
  let second: string

  it('mode tiré : premier passage, seul le tag le plus récent est analysé ; statut en attente', async () => {
    const r = await pollReleases(db.pool)
    expect(r).toMatchObject({ projects: 1, scans: 1, errors: 0 })
    const c = await db.pool.query<{ tag: string, scan_id: string | null, source: string }>('SELECT tag, scan_id::text, source FROM release_candidates WHERE project_id = $1 ORDER BY tag', [projectId])
    expect(c.rows.map(x => [x.tag, !!x.scan_id])).toEqual([['v0.9.0', false], ['v1.0.0', true]])
    first = c.rows[1]!.scan_id!
    const s = await db.pool.query('SELECT trigger, ref, commit_sha FROM scans WHERE id = $1', [first])
    expect(s.rows[0]).toMatchObject({ trigger: 'release', ref: 'v1.0.0', commit_sha: repo.tags![1]!.sha })
    await new Promise(resolve => setTimeout(resolve, 100))
    expect(repo.statuses.at(-1)).toMatchObject({ sha: repo.tags![1]!.sha, context: 'scanoria/release-gate', state: 'pending' })
    // Passage suivant avant l'échéance : rien ; après réinitialisation : aucun tag nouveau.
    expect((await pollReleases(db.pool)).projects).toBe(0)
    resetReleasePolling()
    expect((await pollReleases(db.pool)).scans).toBe(0)
  })

  it('rapport construit, signé par le helper, revérifié ; statut, fichiers joints, contrat 40 une fois', async () => {
    await finishScan(first, 'passed', [{ fp: 'a'.repeat(64), severity: 'high' }, { fp: 'b'.repeat(64), severity: 'low' }])
    await releaseTick(db.pool, requestsDir, () => {})
    const pending = await db.pool.query('SELECT status, report_sha256 FROM release_reports WHERE scan_id = $1', [first])
    expect(pending.rows[0].status).toBe('pending')
    expect((await readdir(join(requestsDir, 'incoming'))).length).toBe(1)
    await helperRound()
    const rr = await db.pool.query('SELECT status, signature, key_fingerprint, report, report_sha256 FROM release_reports WHERE scan_id = $1', [first])
    expect(rr.rows[0].status).toBe('signed')
    const key = await applianceKey()
    expect(rr.rows[0].key_fingerprint).toBe(key!.fingerprint)
    expect(sha256Hex(canonicalBytes(rr.rows[0].report))).toBe(rr.rows[0].report_sha256)
    expect(rr.rows[0].report).toMatchObject({ schema: 'scanoria-release-report/1', tag: 'v1.0.0', scan_id: first, verdict: { value: 'passed' } })
    // Finalisation (même passe) : statut favorable, trois fichiers joints, événement émis.
    expect(repo.statuses.at(-1)).toMatchObject({ state: 'success', context: 'scanoria/release-gate', target_url: `${CONSOLE}/releases/${first}` })
    // Pas de SBOM dans cette analyse : rapport et SARIF seulement.
    expect(repo.releases![0]!.assets.map(a => a.name).sort()).toEqual(['scanoria-release-report.json', 'scanoria-results.sarif'])
    expect(events.filter(e => e.scanId === first)).toHaveLength(1)
    expect(events[0]).toMatchObject({ projectId, verdict: 'passed', reportSha256: rr.rows[0].report_sha256 })
    await releaseTick(db.pool, requestsDir, () => {})
    expect(events.filter(e => e.scanId === first)).toHaveLength(1)
    // Le rapport joint est l'enveloppe signée : vérifiée par scanoria-verify.
    const env = repo.releases![0]!.assets.find(a => a.name === 'scanoria-release-report.json')!.body
    await writeFile(join(dir, 'report.json'), env)
    await writeFile(join(dir, 'appliance.pem'), key!.pem)
    const ok = spawnSync('sh', [VERIFY, join(dir, 'report.json'), '--key', join(dir, 'appliance.pem'), '--commit', repo.tags![1]!.sha, '--require-passed'])
    expect(ok.status, ok.stderr.toString()).toBe(0)
    const bad = spawnSync('sh', [VERIFY, join(dir, 'report.json'), '--key', join(dir, 'appliance.pem'), '--commit', sha()])
    expect(bad.status).toBe(2)
  })

  it('tag déplacé : signalé une fois dans l\'audit, jamais réanalysé', async () => {
    repo.tags![1] = { name: 'v1.0.0', sha: sha() }
    resetReleasePolling()
    expect((await pollReleases(db.pool)).moved).toBe(1)
    resetReleasePolling()
    expect((await pollReleases(db.pool)).moved).toBe(0)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'release.tag.moved'`)).rowCount).toBe(1)
    expect((await db.pool.query(`SELECT 1 FROM scans WHERE trigger = 'release'`)).rowCount).toBe(1)
  })

  it('deuxième release : F2 contre la précédente, défavorable, droit manquant signalé', async () => {
    repo.tags!.push({ name: 'v1.1.0', sha: sha() })
    repo.releases!.push({ id: 2, tag_name: 'v1.1.0', prerelease: true, assets: [] })
    repo.denyAssets = true
    resetReleasePolling()
    expect((await pollReleases(db.pool)).scans).toBe(1)
    second = (await db.pool.query<{ scan_id: string }>(`SELECT scan_id::text FROM release_candidates WHERE tag = 'v1.1.0'`)).rows[0]!.scan_id
    await finishScan(second, 'failed', [{ fp: 'b'.repeat(64), severity: 'low' }, { fp: 'c'.repeat(64), severity: 'critical' }])
    await releaseTick(db.pool, requestsDir, () => {})
    await helperRound()
    const rr = await db.pool.query('SELECT status, previous_scan_id::text, report FROM release_reports WHERE scan_id = $1', [second])
    expect(rr.rows[0]).toMatchObject({ status: 'signed', previous_scan_id: first })
    const cmp = rr.rows[0].report.comparison
    expect(cmp.previous).toMatchObject({ scan_id: first, tag: 'v1.0.0' })
    expect(cmp.introduced.total).toBe(1)
    expect(cmp.fixed.total).toBe(1)
    expect(cmp.unchanged.total).toBe(1)
    expect(repo.statuses.at(-1)).toMatchObject({ state: 'failure', context: 'scanoria/release-gate' })
    expect(repo.releases![1]!.assets).toHaveLength(0)
    const a = await db.pool.query(`SELECT details FROM audit_log WHERE action = 'release.assets' AND target_id = $1`, [second])
    expect(a.rows[0].details.outcome).toBe('missing-permission')
    expect(events.find(e => e.scanId === second)).toMatchObject({ verdict: 'failed' })
  })

  it('routes : page, liste, comparaison, téléchargements, clé publique, client', async () => {
    expect((await call(`/api/releases/${second}`, null)).status).toBe(401)
    const v = await call(`/api/releases/${second}`, 'viewer')
    expect(v.status, JSON.stringify(v.data).slice(0, 2000)).toBe(200)
    expect(v.data).toMatchObject({ tag: 'v1.1.0', report_status: 'signed', verdict: 'failed', signed_verdict: 'failed', gate: { state: 'failure' } })
    expect((v.data.files as Record<string, boolean>)['report.json']).toBe(true)
    expect((v.data.publications as Record<string, { details: { outcome: string } }>).assets?.details.outcome).toBe('missing-permission')
    const l = await call(`/api/releases?project=${projectId}`, 'viewer')
    expect((l.data.items as { tag: string }[]).map(x => x.tag)).toEqual(expect.arrayContaining(['v1.0.0', 'v1.1.0']))
    const c = await call(`/api/releases/${second}/compare?with=${first}`, 'viewer')
    expect(c.data).toMatchObject({ from_scan_id: first, to_scan_id: second, introduced: { total: 1 } })
    expect((await call(`/api/releases/${second}/compare?with=${crypto.randomUUID()}`, 'viewer')).status).toBe(404)
    const rep = await call(`/api/releases/${first}/report.json`, 'viewer')
    expect(rep.status).toBe(200)
    expect(rep.headers.get('content-disposition')).toContain('v1.0.0-report.json')
    expect(rep.data).toMatchObject({ schema: 'scanoria-signed-release-report/1' })
    expect((await call(`/api/releases/${first}/results.sarif`, 'viewer')).data).toMatchObject({ version: '2.1.0' })
    expect((await call(`/api/releases/${first}/../etc`, 'viewer')).status).toBe(404)
    expect((await call(`/api/releases/${first}/other.json`, 'viewer')).status).toBe(404)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'release.download'`)).rowCount).toBeGreaterThanOrEqual(2)
    const k = await call('/api/system/appliance-key', null)
    expect(k.status).toBe(200)
    expect(k.data).toMatchObject({ fingerprint: (await applianceKey())!.fingerprint })
    const cl = await call('/api/releases/client', null)
    expect(cl.status).toBe(200)
    expect(cl.buf.toString('utf8').startsWith('#!/bin/sh')).toBe(true)
    expect((await call(`/api/releases/${crypto.randomUUID()}`, 'viewer')).status).toBe(404)
  })

  it('mode poussé : un tag, une analyse ; même tag rendu tel quel ; tag inconnu, commit faux, mode désactivé', async () => {
    expect((await call(`/api/projects/${projectId}/releases`, 'viewer', { method: 'POST', json: { tag: 'v1.1.0' } })).status).toBe(403)
    const same = await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v1.1.0' } })
    expect(same.status).toBe(200)
    expect(same.data).toMatchObject({ scan_id: second, existing: true, release_url: `/releases/${second}` })
    // Tag noté comme vu au premier passage, sans analyse : la CI peut le demander.
    const old = await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v0.9.0' } })
    expect(old.status).toBe(202)
    expect(old.data.existing).toBe(false)
    expect((await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v9.9.9' } })).code).toBe('E_RELEASE_TAG')
    expect((await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v1.1.0', commit: sha() } })).code).toBe('E_RELEASE_COMMIT')
    expect((await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v1.0.0' } })).code).toBe('E_RELEASE_TAG_MOVED')
    expect((await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: '../x' } })).status).toBe(400)
    await db.pool.query(`UPDATE projects SET release_mode = 'off' WHERE id = $1`, [projectId])
    expect((await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v1.1.0' } })).code).toBe('E_RELEASE_MODE')
    await db.pool.query(`UPDATE projects SET release_mode = 'pull' WHERE id = $1`, [projectId])
  })

  it('I6 : tâche demandée, notes jointes une fois à la release (annexe non signée, marquée IA) ; route notes.md', async () => {
    repo.denyAssets = false
    // Sans connecteur, aucune tâche n'est demandée : rien n'est joint.
    expect((await db.pool.query(`SELECT 1 FROM ai_tasks WHERE kind = 'release-notes'`)).rowCount).toBe(0)
    expect((await call(`/api/releases/${first}/notes.md`, 'viewer')).status).toBe(404)
    // Sortie IA terminée (comme après le traitement par scanoria-ai).
    await db.pool.query(
      `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, status, finished_at, model, model_digest, output)
       VALUES ('release-notes', $1, 'release', $2, 'done', now(), 'modele-test', 'sha256:' || repeat('d', 64), $3::jsonb)`,
      [projectId, first, JSON.stringify({ headline: 'Une faille haute corrigée.', fixed: 'R-high (osv-scanner)', introduced: 'aucun', accepted: 'aucun @equipe' })])
    await releaseTick(db.pool, requestsDir, () => {})
    await releaseTick(db.pool, requestsDir, () => {})
    const notes = repo.releases![0]!.assets.filter(a => a.name === 'scanoria-security-notes.md')
    expect(notes).toHaveLength(1)
    const md = notes[0]!.body.toString('utf8')
    expect(md).toContain('Proposé par IA')
    expect(md).toContain('modele-test')
    expect(md).toContain('non signée')
    expect(md).not.toMatch(/(^|\s)@equipe/)
    const r = await call(`/api/releases/${first}/notes.md`, 'viewer')
    expect(r.status).toBe(200)
    expect(r.buf.toString('utf8')).toContain('Une faille haute corrigée.')
    // Le rapport signé est inchangé par l'annexe.
    const rep = await call(`/api/releases/${first}/report.json`, 'viewer')
    expect(rep.buf.equals(repo.releases![0]!.assets.find(a => a.name === 'scanoria-release-report.json')!.body)).toBe(true)
  })

  it('mode poussé : deux demandes simultanées du même tag, une seule analyse ; forge en erreur : 503, commit de la CI jamais retenu', async () => {
    const tag = 'v1.3.0'
    const commit = sha()
    repo.tags!.push({ name: tag, sha: commit })
    const [a, b] = await Promise.all([
      call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag } }),
      call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag } }),
    ])
    expect([a.status, b.status].sort()).toEqual([200, 202])
    expect(a.data.scan_id).toBe(b.data.scan_id)
    const scans = await db.pool.query(`SELECT count(*)::int AS n FROM scans WHERE project_id = $1 AND trigger = 'release' AND ref = $2`, [projectId, tag])
    expect(scans.rows[0].n).toBe(1)
    const rc = await db.pool.query<{ scan_id: string }>('SELECT scan_id::text FROM release_candidates WHERE project_id = $1 AND tag = $2', [projectId, tag])
    expect(rc.rows[0]!.scan_id).toBe(a.data.scan_id)

    repo.failTags = true
    try {
      const down = await call(`/api/projects/${projectId}/releases`, 'operator', { method: 'POST', json: { tag: 'v1.4.0', commit: sha() } })
      expect(down.status).toBe(503)
      expect(down.code).toBe('E_RELEASE_FORGE')
      expect((await db.pool.query('SELECT 1 FROM release_candidates WHERE project_id = $1 AND tag = $2', [projectId, 'v1.4.0'])).rowCount).toBe(0)
    }
    finally {
      repo.failTags = false
    }
  })

  it('signature falsifiée dans le résultat du helper : refusée, rapport en erreur, statut bloquant', async () => {
    const tag = 'v1.2.0'
    repo.tags!.push({ name: tag, sha: sha() })
    resetReleasePolling()
    await pollReleases(db.pool)
    const id = (await db.pool.query<{ scan_id: string }>('SELECT scan_id::text FROM release_candidates WHERE tag = $1', [tag])).rows[0]!.scan_id
    await finishScan(id, 'passed', [])
    await releaseTick(db.pool, requestsDir, () => {})
    execFileSync(HELPER, ['run'], { env: { ...process.env, SCANORIA_TEST_ROOT: testRoot, SCANORIA_TEST_BIN: join(dir, 'stubs'), PYTHONDONTWRITEBYTECODE: '1' }, stdio: 'pipe' })
    // Le résultat revient avec la signature d'un autre contenu : la console revérifie et refuse.
    const done = join(requestsDir, 'done')
    for (const name of await readdir(done)) {
      const res = JSON.parse(await readFile(join(done, name), 'utf8'))
      if (res.output?.scan_id === id) {
        res.output.signature = Buffer.alloc(64, 7).toString('base64')
        await writeFile(join(done, name), JSON.stringify(res))
      }
    }
    await ingestResults(db.pool, requestsDir, memory)
    await releaseTick(db.pool, requestsDir, () => {})
    const rr = await db.pool.query('SELECT status, error FROM release_reports WHERE scan_id = $1', [id])
    expect(rr.rows[0].status).toBe('error')
    expect(String(rr.rows[0].error)).toContain('E_SIGNATURE')
    expect(repo.statuses.filter(x => x.sha === repo.tags!.at(-1)!.sha).at(-1)).toMatchObject({ state: 'failure' })
    expect(events.find(e => e.scanId === id)).toBeUndefined()
    expect((await call(`/api/releases/${id}/report.json`, 'viewer')).code).toBe('E_RELEASE_NOT_SIGNED')
  })

  it('rapport resté « pending » au-delà du délai : erreur E_SIGN_TIMEOUT, statut bloquant', async () => {
    const tag = 'v1.5.0'
    repo.tags!.push({ name: tag, sha: sha() })
    resetReleasePolling()
    await pollReleases(db.pool)
    const id = (await db.pool.query<{ scan_id: string }>('SELECT scan_id::text FROM release_candidates WHERE tag = $1', [tag])).rows[0]!.scan_id
    await finishScan(id, 'passed', [])
    // Arrêt simulé entre l'insertion du rapport et la demande : aucune demande ne reviendra.
    await releaseTick(db.pool, requestsDir, () => {})
    await db.pool.query(`DELETE FROM helper_requests WHERE type = 'sign-release-report' AND params ->> 'scan_id' = $1`, [id])
    await db.pool.query(`UPDATE release_reports SET created_at = now() - interval '2 hours' WHERE scan_id = $1`, [id])
    expect(await expireStaleReports(db.pool)).toBe(1)
    await releaseTick(db.pool, requestsDir, () => {})
    const rr = await db.pool.query('SELECT status, error FROM release_reports WHERE scan_id = $1', [id])
    expect(rr.rows[0]).toMatchObject({ status: 'error', error: 'E_SIGN_TIMEOUT' })
    expect(repo.statuses.filter(x => x.sha === repo.tags!.at(-1)!.sha).at(-1)).toMatchObject({ state: 'failure' })
  })
})
