// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// b37-live (chantier A de la 0.8, CLAUDE.md § 7) : gate de release contre un
// VRAI Forgejo, un vrai PostgreSQL et le vrai helper (qui crée et garde la clé
// Ed25519 de l'appliance). Tag et release créés dans Forgejo → interrogation
// (mode tiré) → analyse de release → rapport signé par le helper → statut
// scanoria/release-gate lu dans Forgejo → fichiers joints à la release,
// téléchargés depuis Forgejo et vérifiés par scanoria-verify ; deuxième tag
// sur un nouveau commit avec la comparaison F2 ; tag déplacé signalé, jamais
// réanalysé. Ignoré sans SCANORIA_FORGEJO_URL (lancé seulement par b37-live).

import { execFileSync, spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { IngestMemory, ingestResults } from '../../server/utils/ingest'
import { createHttpsTransport, setForgeTransport } from '../../server/forges/http'
import { setConsoleUrl } from '../../server/forges/context'
import { createForge } from '../../server/projects/forges'
import { discoverForge } from '../../server/projects/discover'
import { getForge } from '../../server/forges'
import { pollReleases, resetReleasePolling } from '../../server/release/poll'
import { releaseTick } from '../../server/release/tick'
import { applianceKey } from '../../server/release/sign'

const FORGEJO = process.env.SCANORIA_FORGEJO_URL ?? ''
const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url))
const HELPER = join(REPO_ROOT, 'src/rootfs/usr/sbin/scanoria-helper')
const VERIFY = join(REPO_ROOT, 'src/rootfs/usr/share/scanoria/client/scanoria-verify')
const CONSOLE = 'https://analyse.exemple.test'

// Réponses JSON de Forgejo lues en profondeur.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any

describe.skipIf(!DATABASE_URL || !FORGEJO)('b37-live : vrai Forgejo, gate de release', { timeout: 120_000 }, () => {
  let db: TestDatabase
  let dir: string
  let testRoot: string
  let requestsDir: string
  let projectId: string
  const memory = new IngestMemory()
  const tokens = JSON.parse(readFileSync(process.env.SCANORIA_FORGEJO_TOKENS ?? '/dev/null', 'utf8') || '{}') as Record<'admin' | 'bot', string>
  const ca = readFileSync(process.env.SCANORIA_FORGE_CA ?? '/dev/null', 'utf8')
  const transport = createHttpsTransport({ ca, refuseAddress: () => false })

  async function fj(token: string, method: string, path: string, body?: unknown): Promise<Json> {
    const res = await transport(`${FORGEJO}/api/v1${path}`, {
      method, headers: { 'authorization': `token ${token}`, 'content-type': 'application/json', 'accept': 'application/json' },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const text = await res.text()
    if (res.status >= 400) throw new Error(`Forgejo ${method} ${path} : ${res.status} ${text.slice(0, 300)}`)
    return text ? JSON.parse(text) : null
  }
  async function download(url: string): Promise<Buffer> {
    const res = await transport(url, { method: 'GET', headers: { authorization: `token ${tokens.admin}` } })
    expect(res.status).toBe(200)
    return Buffer.from(await res.arrayBuffer())
  }
  // Dernier statut du contexte (Forgejo garde l'historique ; l'ordre de la liste n'est pas garanti).
  const gateStatus = async (sha: string) => ((await fj(tokens.admin, 'GET', `/repos/equipe/app/commits/${sha}/statuses?limit=50`)) as Json[])
    .filter(s => s.context === 'scanoria/release-gate').sort((a, b) => b.id - a.id)[0]

  async function tag(name: string, prerelease: boolean): Promise<{ sha: string, releaseId: number }> {
    await fj(tokens.admin, 'POST', '/repos/equipe/app/tags', { tag_name: name, target: 'main' })
    const rel = await fj(tokens.admin, 'POST', '/repos/equipe/app/releases', { tag_name: name, name, prerelease })
    const t = await fj(tokens.admin, 'GET', `/repos/equipe/app/tags/${name}`)
    return { sha: t.commit.sha, releaseId: rel.id }
  }
  async function scanOf(name: string): Promise<string> {
    return (await db.pool.query<{ scan_id: string }>('SELECT scan_id::text FROM release_candidates WHERE tag = $1', [name])).rows[0]!.scan_id
  }
  /** Fin d'analyse : verdict et résultats (les scanners ne tournent pas dans ce test). */
  async function finish(scanId: string, verdict: string, fps: [string, string][]) {
    await db.pool.query(`UPDATE scans SET status = 'done', verdict = $2, verdict_details = '{"reasons": []}'::jsonb, started_at = now(), finished_at = now() WHERE id = $1`, [scanId, verdict])
    for (const [fp, severity] of fps) {
      const r = await db.pool.query<{ id: string }>(
        `INSERT INTO findings (project_id, fingerprint, tool, rule_id, category, severity, title, path, status)
         VALUES ($1, $2, 'gitleaks', 'generic-api-key', 'secrets', $3, 'Secret probable', 'src/a.ts', 'new')
         ON CONFLICT (project_id, fingerprint) DO UPDATE SET title = EXCLUDED.title RETURNING id`, [projectId, fp, severity])
      await db.pool.query('INSERT INTO scan_findings (scan_id, finding_id, is_new) VALUES ($1, $2, true) ON CONFLICT DO NOTHING', [scanId, r.rows[0]!.id])
    }
  }
  async function signRound() {
    await releaseTick(db.pool, requestsDir, () => {})
    execFileSync(HELPER, ['run'], { env: { ...process.env, SCANORIA_TEST_ROOT: testRoot, SCANORIA_TEST_BIN: join(dir, 'stubs'), PYTHONDONTWRITEBYTECODE: '1' }, stdio: 'pipe' })
    await ingestResults(db.pool, requestsDir, memory)
    await releaseTick(db.pool, requestsDir, () => {})
  }
  async function verifyAsset(releaseId: number, commit: string, extra: string[] = []) {
    const assets = (await fj(tokens.admin, 'GET', `/repos/equipe/app/releases/${releaseId}/assets`)) as Json[]
    const report = assets.find(a => a.name === 'scanoria-release-report.json')
    expect(report, JSON.stringify(assets.map(a => a.name))).toBeTruthy()
    await writeFile(join(dir, 'report.json'), await download(report.browser_download_url))
    await writeFile(join(dir, 'appliance.pem'), (await applianceKey())!.pem)
    return spawnSync('sh', [VERIFY, join(dir, 'report.json'), '--key', join(dir, 'appliance.pem'), '--commit', commit, ...extra])
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-b37-'))
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
    setForgeTransport(transport)
    setConsoleUrl(CONSOLE)
    await fj(tokens.admin, 'POST', '/orgs', { username: 'equipe', visibility: 'public' })
    await fj(tokens.admin, 'POST', '/orgs/equipe/repos', { name: 'app', auto_init: true, default_branch: 'main', private: false })
    await fj(tokens.admin, 'PUT', '/repos/equipe/app/collaborators/scanoria-bot', { permission: 'write' })
    const res = await createForge(db.pool, { kind: 'forgejo', name: 'Forgejo', base_url: FORGEJO, token: tokens.bot, discovery: true }, { type: 'system' })
    projectId = (await discoverForge(db.pool, (await getForge(db.pool, res.forge.id))!)).created[0]!
    expect(projectId).toBeTruthy()
  }, 120_000)

  afterAll(async () => {
    resetReleasePolling()
    setConsoleUrl()
    setForgeTransport()
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    delete process.env.NUXT_RELEASES_DIR
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  let v1: { sha: string, releaseId: number }

  it('1. tag et release dans Forgejo → interrogation → analyse de release, statut en attente', async () => {
    v1 = await tag('v1.0.0', true)
    const r = await pollReleases(db.pool)
    expect(r).toMatchObject({ scans: 1, errors: 0 })
    const scan = await scanOf('v1.0.0')
    expect((await db.pool.query('SELECT trigger, commit_sha FROM scans WHERE id = $1', [scan])).rows[0]).toMatchObject({ trigger: 'release', commit_sha: v1.sha })
    await new Promise(resolve => setTimeout(resolve, 500))
    expect(await gateStatus(v1.sha)).toMatchObject({ status: 'pending' })
  })

  it('2. rapport signé par le helper → statut favorable → fichiers joints vérifiés par scanoria-verify', async () => {
    await finish(await scanOf('v1.0.0'), 'passed', [['a'.repeat(64), 'low']])
    await signRound()
    const st = await gateStatus(v1.sha)
    expect(st).toMatchObject({ status: 'success' })
    expect(st.target_url).toBe(`${CONSOLE}/releases/${await scanOf('v1.0.0')}`)
    const ok = await verifyAsset(v1.releaseId, v1.sha, ['--require-passed'])
    expect(ok.status, ok.stderr.toString()).toBe(0)
    const other = await verifyAsset(v1.releaseId, 'f'.repeat(40))
    expect(other.status).toBe(2)
    // Clé jamais régénérée, privée jamais lisible hors du helper.
    expect(readFileSync(join(testRoot, 'etc/scanoria/keys/appliance.ed25519'), 'utf8')).toContain('PRIVATE KEY')
  })

  it('3. deuxième tag sur un nouveau commit : comparaison F2, défavorable, statut bloquant', async () => {
    await fj(tokens.admin, 'POST', '/repos/equipe/app/contents/src/b.ts', { content: Buffer.from('export const b = 1\n').toString('base64'), message: 'ajout', branch: 'main' })
    const v2 = await tag('v1.1.0', false)
    expect(v2.sha).not.toBe(v1.sha)
    resetReleasePolling()
    expect((await pollReleases(db.pool)).scans).toBe(1)
    const scan = await scanOf('v1.1.0')
    await finish(scan, 'failed', [['b'.repeat(64), 'critical']])
    await signRound()
    expect(await gateStatus(v2.sha)).toMatchObject({ status: 'failure' })
    const rr = await db.pool.query('SELECT status, report FROM release_reports WHERE scan_id = $1', [scan])
    expect(rr.rows[0].status).toBe('signed')
    expect(rr.rows[0].report.comparison).toMatchObject({ previous: { tag: 'v1.0.0' }, introduced: { total: 1 }, fixed: { total: 1 } })
    const ok = await verifyAsset(v2.releaseId, v2.sha)
    expect(ok.status, ok.stderr.toString()).toBe(0)
    expect((await verifyAsset(v2.releaseId, v2.sha, ['--require-passed'])).status).toBe(4)
  })

  it('4. tag déplacé dans Forgejo : signalé une fois, jamais réanalysé', async () => {
    await fj(tokens.admin, 'DELETE', '/repos/equipe/app/releases/tags/v1.0.0').catch(() => null)
    await fj(tokens.admin, 'DELETE', '/repos/equipe/app/tags/v1.0.0')
    await fj(tokens.admin, 'POST', '/repos/equipe/app/tags', { tag_name: 'v1.0.0', target: 'main' })
    resetReleasePolling()
    const r = await pollReleases(db.pool)
    expect(r).toMatchObject({ moved: 1, scans: 0 })
    resetReleasePolling()
    expect((await pollReleases(db.pool)).moved).toBe(0)
    expect((await db.pool.query(`SELECT 1 FROM scans WHERE trigger = 'release'`)).rowCount).toBe(2)
    expect((await db.pool.query(`SELECT details FROM audit_log WHERE action = 'release.tag.moved'`)).rows[0].details).toMatchObject({ tag: 'v1.0.0', known_commit: v1.sha })
  })
})
