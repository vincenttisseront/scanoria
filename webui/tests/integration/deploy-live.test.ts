// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// b40-live : déploiement après verdict favorable (0.8, chantier D) contre un
// VRAI Forgejo (API, Actions, registre de conteneurs OCI) et le VRAI helper
// root (mode test, clé Ed25519 de l'appliance) :
//   - verdict défavorable : refus enregistré, rien dans le registre ni dans
//     la forge ;
//   - verdict favorable : empreinte de la candidate résolue, attestation
//     signée par le helper (demande sign-attestation déposée par la console,
//     traitée par scanoria-helper run, résultat relu), image copiée par
//     empreinte, attestation poussée au format cosign, PR GitOps ouverte et
//     jamais fusionnée, workflow_dispatch déclenché une seule fois et suivi.
// La vérification par scanoria-verify-attestation et par cosign est faite par
// tests/b40-live.sh à partir des fichiers écrits dans SCANORIA_DEPLOY_OUT.
// Ignoré sans SCANORIA_DEPLOY_FORGEJO_URL (lancé seulement par b40-live).

import { execFile } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { createTestDatabase, type TestDatabase } from '../helpers/db'
import { loadConfig, setConfig } from '../../server/utils/config'
import { closePool } from '../../server/utils/db'
import { IngestMemory, ingestResults } from '../../server/utils/ingest'
import { createUser } from '../../server/utils/users'
import { createHttpsTransport, setForgeTransport } from '../../server/forges/http'
import { setConsoleUrl } from '../../server/forges/context'
import { createForge } from '../../server/projects/forges'
import { RegistryClient, createRegistryTransport, setRegistryTransport } from '../../server/deploy/registry'
import { createTarget } from '../../server/deploy/targets'
import { deployPass } from '../../server/deploy/engine'
import { listDeployments } from '../../server/deploy/runs'
import { ed25519PublicKey, verifyEnvelope } from '../../server/attest/dsse'

const run = promisify(execFile)
const FORGEJO = process.env.SCANORIA_DEPLOY_FORGEJO_URL ?? ''
const ROOT_DIR = join(__dirname, '..', '..', '..')

describe.skipIf(!FORGEJO)('b40-live : déploiement contre un vrai Forgejo et le vrai helper', () => {
  type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any -- réponses de l'API Forgejo lues librement
  const tokens = JSON.parse(readFileSync(process.env.SCANORIA_DEPLOY_TOKENS ?? '/dev/null', 'utf8') || '{}') as Record<'admin' | 'bot', string>
  const ca = readFileSync(process.env.SCANORIA_DEPLOY_CA ?? '/dev/null', 'utf8')
  const helperRoot = process.env.SCANORIA_DEPLOY_HELPER_ROOT ?? ''
  const out = process.env.SCANORIA_DEPLOY_OUT ?? ''
  // Appels directs du test (préparation, vérifications) : même AC jetable que la console.
  const forgeHttps = createHttpsTransport({ ca, refuseAddress: () => false })
  const REG = FORGEJO ? new URL(FORGEJO).host : 'forge.exemple.test'
  const CANDIDATE = `${REG}/scanoria-bot/candidat-app`
  const VALIDATED = `${REG}/scanoria-bot/valide-app`
  const requestsDir = join(helperRoot, 'var/lib/scanoria/requests')
  const memory = new IngestMemory()
  let db: TestDatabase
  let dir: string
  let projectId: string
  let adminId: number
  let candidateDigest: string

  async function fj(token: string, method: string, path: string, body?: unknown): Promise<Json | null> {
    const res = await forgeHttps(`${FORGEJO}/api/v1${path}`, {
      method,
      headers: { 'authorization': `token ${token}`, 'content-type': 'application/json', 'accept': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
    const text = await res.text()
    if (!res.ok && res.status !== 404) throw new Error(`Forgejo ${method} ${path} : HTTP ${res.status} ${text.slice(0, 300)}`)
    return res.status === 404 ? null : text ? JSON.parse(text) as Json : {}
  }

  /** Le helper root traite les demandes déposées, la console relit les résultats (comme sur l'appliance). */
  async function helperCycle() {
    await run(join(ROOT_DIR, 'src/rootfs/usr/sbin/scanoria-helper'), ['run'], { env: { ...process.env, SCANORIA_TEST_ROOT: helperRoot, PYTHONDONTWRITEBYTECODE: '1' } })
    await ingestResults(db.pool, requestsDir, memory)
  }

  async function scan(verdict: string, tag: string): Promise<string> {
    const sha = (await fj(tokens.admin, 'GET', '/repos/equipe/app/branches/main'))!.commit.id as string
    const id = (await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, verdict, finished_at)
       SELECT id, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, 'release', 90, $2, $3, profile_id, gate_id, 'done', $4, now()
         FROM projects WHERE id = $1 RETURNING id::text`, [projectId, `refs/tags/${tag}`, sha, verdict])).rows[0]!.id
    await db.pool.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source, scan_id) VALUES ($1, $2, $3, 'pull', $4)`, [projectId, tag, sha, id])
    await db.pool.query(
      `INSERT INTO release_reports (scan_id, project_id, tag, commit_sha, report, report_sha256, status, signature, key_fingerprint, signed_at)
       VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, 'signed', $6, $7, now())`,
      [id, projectId, tag, sha, createHash('sha256').update(id).digest('hex'), `${'A'.repeat(86)}==`, 'f'.repeat(64)])
    // Relevé root écrit par le helper quand il signe le rapport de release
    // (chantier A, release.record_signed_report) : simulé au même chemin.
    const ledger = join(helperRoot, 'var/lib/scanoria/release/signed')
    await mkdir(ledger, { recursive: true, mode: 0o700 })
    await writeFile(join(ledger, `${id}.json`), JSON.stringify({
      scan_id: id, report_sha256: createHash('sha256').update(id).digest('hex'), commit_sha: sha, tag,
      verdict: verdict === 'passed' ? 'passed' : 'failed', key_fingerprint: 'f'.repeat(64), signed_at: new Date().toISOString().slice(0, 19) + 'Z',
    }), { mode: 0o600 })
    return id
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-b40-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: requestsDir,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    // Forge et registre sur 127.0.0.1 derrière l'AC jetable : seules différences avec l'appliance.
    setForgeTransport(forgeHttps)
    setRegistryTransport(createRegistryTransport({ ca, refuseAddress: () => false }))
    setConsoleUrl('https://analyse.exemple.test')
    adminId = Number((await createUser(db.pool, { username: 'admin-b40', role: 'admin', password: randomBytes(12).toString('hex') })).id)

    // Dépôts : l'application (workflow de déploiement) et le dépôt GitOps.
    await fj(tokens.admin, 'POST', '/orgs', { username: 'equipe', visibility: 'private' })
    for (const name of ['app', 'deploiement']) {
      await fj(tokens.admin, 'POST', '/orgs/equipe/repos', { name, auto_init: true, default_branch: 'main', private: true })
      await fj(tokens.admin, 'PUT', `/repos/equipe/${name}/collaborators/scanoria-bot`, { permission: 'write' })
    }
    const workflow = [
      'on:',
      '  workflow_dispatch:',
      '    inputs:',
      '      scanoria_report: { required: true, type: string }',
      '      scanoria_commit: { required: true, type: string }',
      '      scanoria_tag: { required: false, type: string }',
      '      scanoria_image: { required: false, type: string }',
      'jobs:',
      '  deploy:',
      '    runs-on: docker',
      '    steps:',
      '      - run: echo "$SCANORIA_IMAGE"',
      '        env:',
      '          SCANORIA_IMAGE: ${{ inputs.scanoria_image }}',
      '',
    ].join('\n')
    await fj(tokens.admin, 'POST', '/repos/equipe/app/contents/.forgejo/workflows/deploy.yml', { content: Buffer.from(workflow).toString('base64'), message: 'déploiement', branch: 'main' })
    await fj(tokens.admin, 'POST', '/repos/equipe/deploiement/contents/apps/app.yaml', {
      content: Buffer.from(`apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: ${VALIDATED}:v0.9.0@sha256:${'0'.repeat(64)}\n`).toString('base64'),
      message: 'état initial', branch: 'main',
    })

    // Image candidate poussée dans le vrai registre de Forgejo (contenu généré à l'exécution).
    const push = new RegistryClient(REG, { username: 'scanoria-bot', password: tokens.bot })
    const layer = randomBytes(2048)
    const config = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux', rootfs: { type: 'layers', diff_ids: [] } }))
    const sha = (b: Buffer) => `sha256:${createHash('sha256').update(b).digest('hex')}`
    const repo = 'scanoria-bot/candidat-app'
    await push.putBlob(repo, sha(layer), layer, layer.length)
    await push.putBlob(repo, sha(config), config, config.length)
    const manifest = Buffer.from(JSON.stringify({
      schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json',
      config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: sha(config), size: config.length },
      layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: sha(layer), size: layer.length }],
    }))
    await push.putManifest(repo, 'v1.0.0', 'application/vnd.oci.image.manifest.v1+json', manifest)
    candidateDigest = sha(manifest)

    // Forge enregistrée avec le jeton du compte de service, projet de l'application.
    const forge = await createForge(db.pool, { kind: 'forgejo', name: 'Forgejo', base_url: FORGEJO, token: tokens.bot, discovery: false }, { type: 'system' })
    projectId = (await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, forge_id, repo_full_name)
       VALUES ('app', 'App', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), $1, 'equipe/app')
       RETURNING id::text`, [forge.forge.id])).rows[0]!.id
    const actor = { type: 'user' as const, userId: adminId, username: 'admin-b40' }
    await createTarget(db.pool, projectId, { kind: 'registry-promotion', environment: 'production', on_trigger: 'release', enabled: true,
      config: { source: CANDIDATE, source_tag: '{tag}', destination: VALIDATED, destination_tag: '{tag}' }, credential: { username: 'scanoria-bot', value: tokens.bot } }, actor)
    await createTarget(db.pool, projectId, { kind: 'gitops-pr', environment: 'production', on_trigger: 'release', enabled: true,
      config: { repo: 'equipe/deploiement', base: 'main', files: [{ path: 'apps/app.yaml', image: VALIDATED }] } } as never, actor)
    await createTarget(db.pool, projectId, { kind: 'cd-trigger', environment: 'production', on_trigger: 'release', enabled: true,
      config: { provider: 'forge', workflow: 'deploy.yml', inputs: ['scanoria_report', 'scanoria_commit', 'scanoria_tag', 'scanoria_image'] } } as never, actor)
  }, 120_000)

  afterAll(async () => {
    setConsoleUrl()
    setForgeTransport()
    setRegistryTransport()
    await closePool()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('1. verdict défavorable : refus enregistré, rien dans le registre ni la forge', async () => {
    const s = await scan('failed', 'v0.9.9')
    await deployPass(db.pool)
    await helperCycle()
    await deployPass(db.pool)
    const runs = await listDeployments(db.pool, { scanId: s })
    expect(runs).toHaveLength(3)
    expect(runs.every(r => r.status === 'refused' && r.refused_reason === 'verdict-not-passed')).toBe(true)
    expect(await fj(tokens.admin, 'GET', '/repos/equipe/deploiement/pulls?state=all')).toEqual([])
    expect((await db.pool.query(`SELECT 1 FROM helper_requests WHERE type = 'sign-attestation'`)).rowCount).toBe(0)
    const reader = new RegistryClient(REG, { username: 'scanoria-bot', password: tokens.bot })
    await expect(reader.resolve('scanoria-bot/valide-app', candidateDigest)).rejects.toThrow()
  })

  it('2. verdict favorable : attestation signée par le helper, promotion, PR GitOps, CD déclenchée et suivie', async () => {
    const s = await scan('passed', 'v1.0.0')
    let runs = await listDeployments(db.pool, { scanId: s })
    for (let i = 0; i < 30; i++) {
      await deployPass(db.pool)
      await helperCycle()
      runs = await listDeployments(db.pool, { scanId: s })
      const cd = runs.find(r => r.kind === 'cd-trigger')
      if (runs.length === 3 && cd && cd.status !== 'pending') break
      await new Promise(r => setTimeout(r, 1000))
    }
    const by = (k: string) => runs.find(r => r.kind === k)!
    expect(by('registry-promotion')).toMatchObject({ status: 'succeeded', external_id: candidateDigest })

    // Attestation : signée par la clé de l'appliance (helper), poussée dans le registre.
    const att = (await db.pool.query<{ status: string, envelope: unknown, pushed_to: string, error: string | null }>('SELECT status, envelope, pushed_to, error FROM attestations WHERE scan_id = $1', [s])).rows
    expect(att).toHaveLength(1)
    expect(att[0]).toMatchObject({ status: 'pushed', error: null, pushed_to: `${VALIDATED}:${candidateDigest.replace(':', '-')}.att` })
    const { stdout: der } = await run('openssl', ['pkey', '-in', join(helperRoot, 'etc/scanoria/keys/appliance.ed25519'), '-pubout', '-outform', 'DER'], { encoding: 'buffer' })
    const raw = (der as unknown as Buffer).subarray(-32)
    const v = verifyEnvelope(att[0]!.envelope as never, raw, candidateDigest)
    expect(v?.statement.subject).toEqual([{ name: VALIDATED, digest: { sha256: candidateDigest.slice(7) } }])
    expect(v?.statement.predicate).toMatchObject({ scan_id: s, verdict: 'passed', tag: 'v1.0.0' })
    expect(ed25519PublicKey(raw)).toBeTruthy()

    // Image copiée par empreinte, étiquette posée, empreinte relue.
    const reader = new RegistryClient(REG, { username: 'scanoria-bot', password: tokens.bot })
    expect(await reader.resolve('scanoria-bot/valide-app', candidateDigest)).toBe(candidateDigest)
    expect(await reader.resolve('scanoria-bot/valide-app', 'v1.0.0')).toBe(candidateDigest)

    // PR GitOps : ouverte, jamais fusionnée, seule l'empreinte change.
    const gitops = by('gitops-pr')
    expect(gitops.status).toBe('succeeded')
    const pr = await fj(tokens.admin, 'GET', `/repos/equipe/deploiement/pulls/${gitops.external_id}`)
    expect(pr).toMatchObject({ state: 'open', merged: false })
    expect(pr!.head.ref).toMatch(/^scanoria\/promote\/production-[0-9a-f]{8}$/)
    const file = await fj(tokens.admin, 'GET', `/repos/equipe/deploiement/contents/apps/app.yaml?ref=${encodeURIComponent(pr!.head.ref)}`)
    expect(Buffer.from(file!.content, 'base64').toString()).toContain(`image: ${VALIDATED}:v0.9.0@${candidateDigest}\n`)
    const main = await fj(tokens.admin, 'GET', '/repos/equipe/deploiement/contents/apps/app.yaml?ref=main')
    expect(Buffer.from(main!.content, 'base64').toString()).toContain(`@sha256:${'0'.repeat(64)}`)

    // Pour b40-live.sh : vérification par scanoria-verify-attestation et cosign.
    if (out) {
      await writeFile(join(out, 'image.txt'), `${VALIDATED}@${candidateDigest}\n`)
      await writeFile(join(out, 'candidate.txt'), `${CANDIDATE}@${candidateDigest}\n`)
    }

    // CD : déclenchée une fois (réservée avant l'appel), suivie sans redéclenchement.
    const cd = by('cd-trigger')
    if (out) await writeFile(join(out, 'cd.json'), JSON.stringify({ status: cd.status, external_id: cd.external_id, error: cd.error }))
    expect({ status: cd.status, error: cd.error }).toMatchObject({ status: expect.stringMatching(/^(running|succeeded)$/) })
    const audit = await db.pool.query<{ details: { run_id: string | null } }>(`SELECT details FROM audit_log WHERE action = 'deploy.cd.trigger'`)
    expect(audit.rows).toHaveLength(1)
    await deployPass(db.pool)
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'deploy.cd.trigger'`)).rowCount).toBe(1)
    if (cd.external_id) {
      const r = await fj(tokens.admin, 'GET', `/repos/equipe/app/actions/runs/${cd.external_id}`)
      expect(r).not.toBeNull()
    }
  }, 120_000)
})
