// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D de la 0.8 contre PostgreSQL, une fausse forge Forgejo et un faux
// registre OCI : refus sans verdict favorable, une exécution par cible et par
// analyse, promotion par empreinte avec attestation signée (helper simulé),
// PR GitOps jamais fusionnée, CD déclenchée une seule fois puis suivie, arrêt
// net après un échec, chaîne autonome (J16) traitée une fois par analyse.

import { createHash, generateKeyPairSync, randomBytes, sign as edSign } from 'node:crypto'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { fakeRegistry, type FakeRegistry } from '../helpers/fake-registry'
import { fakeToken } from '../helpers/fake-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { encryptSecret } from '../../server/utils/secrets'
import { hashPassword } from '../../server/utils/password'
import { setForgeRetryDelays, setForgeTransport } from '../../server/forges/http'
import { setConsoleUrl } from '../../server/forges/context'
import { setRegistryTransport } from '../../server/deploy/registry'
import { deployPass } from '../../server/deploy/engine'
import { AUTOMERGE_ACTION } from '../../server/deploy/autonomous'
import { createTarget, getTarget, updateTarget, proposeTargets, listTargets } from '../../server/deploy/targets'
import { projectChain } from '../../server/deploy/chain'
import { listDeployments } from '../../server/deploy/runs'
import { registerDeployListeners } from '../../server/deploy/listen'
import { PREDICATE_TYPE, pae, PAYLOAD_TYPE, verifyEnvelope } from '../../server/attest/dsse'

const FORGE = 'forge.exemple.test'
const REG = 'registre.exemple.test'
const CONSOLE = 'https://analyse.exemple.test'

interface Call { method: string, path: string, body: unknown }

/** Fausse forge Forgejo, juste ce que le déploiement utilise. */
function fakeForgejo() {
  const calls: Call[] = []
  const files = new Map<string, string>()
  const state = { runStatus: 'running', runConclusion: '', prBody: '', prOpen: true, dispatchFails: false, heads: new Map<number, string>() }
  const json = (status: number, data: unknown) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
  const handler = async (url: string, init: RequestInit): Promise<Response> => {
    const u = new URL(url)
    const method = (init.method ?? 'GET').toUpperCase()
    const raw = typeof init.body === 'string' ? init.body : init.body instanceof Uint8Array ? Buffer.from(init.body).toString('utf8') : null
    const body = raw ? JSON.parse(raw) as unknown : null
    calls.push({ method, path: u.pathname, body })
    if (u.host !== FORGE) return json(404, {})
    const p = u.pathname.replace('/api/v1/repos/', '')
    let m = /^equipe\/deploiement\/contents\/(.+)$/.exec(p)
    if (m && method === 'GET') {
      const c = files.get(decodeURIComponent(m[1]!))
      return c === undefined ? json(404, {}) : json(200, { type: 'file', content: Buffer.from(c).toString('base64'), sha: 'a'.repeat(40), size: c.length })
    }
    if (p === 'equipe/deploiement/contents' && method === 'POST') return json(201, { commit: { sha: 'c'.repeat(40) } })
    if (p === 'equipe/deploiement/pulls' && method === 'POST') return json(201, { number: 7, html_url: `https://${FORGE}/equipe/deploiement/pulls/7` })
    if (/^equipe\/app\/actions\/workflows\/deploy\.yml\/dispatches$/.test(p)) {
      if (state.dispatchFails) return json(422, {})
      return json(201, { id: 42, html_url: `https://${FORGE}/equipe/app/actions/runs/42` })
    }
    if (p === 'equipe/app/actions/runs/42') return json(200, { status: state.runStatus, conclusion: state.runConclusion, html_url: `https://${FORGE}/equipe/app/actions/runs/42` })
    m = /^equipe\/app\/pulls\/(\d+)$/.exec(p)
    if (m && method === 'GET') return json(200, { body: state.prBody, state: state.prOpen ? 'open' : 'closed', head: { sha: state.heads.get(Number(m[1])) ?? null } })
    if (/^equipe\/app\/pulls\/\d+\/merge$/.test(p)) return json(200, {})
    return json(404, {})
  }
  return { calls, files, state, handler }
}

describe.skipIf(!DATABASE_URL)('déploiement après verdict favorable (chantier D 0.8, PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let forge: ReturnType<typeof fakeForgejo>
  let reg: FakeRegistry
  let projectId: string
  let adminId: number
  const keys = generateKeyPairSync('ed25519')
  const rawPub = (keys.publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32)
  const fingerprint = createHash('sha256').update(rawPub).digest('hex')
  const admin = () => ({ type: 'user' as const, userId: adminId, username: 'admin' })

  async function scan(p: { verdict: string, trigger?: string, ref?: string, tag?: string | null, signed?: boolean, pr?: number }): Promise<string> {
    const sha = randomBytes(20).toString('hex')
    const r = await db.pool.query<{ id: string }>(
      `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id, status, verdict, finished_at, pull_request)
       SELECT id, COALESCE((SELECT max(number) FROM scans WHERE project_id = $1), 0) + 1, $2, 50, $3, $4, profile_id, gate_id, 'done', $5, now(), $6
         FROM projects WHERE id = $1 RETURNING id::text`,
      [projectId, p.trigger ?? 'release', p.ref ?? 'refs/tags/v1.2.0', sha, p.verdict,
        p.pr ? JSON.stringify({ number: p.pr, base_sha: 'b'.repeat(40), head_sha: sha }) : null])
    const id = r.rows[0]!.id
    if (p.pr) forge.state.heads.set(p.pr, sha)
    const tag = p.tag === undefined ? 'v1.2.0' : p.tag
    if (tag && !p.pr) {
      await db.pool.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source, scan_id) VALUES ($1, $2, $3, 'pull', $4)
                           ON CONFLICT (project_id, tag) DO UPDATE SET scan_id = EXCLUDED.scan_id, commit_sha = EXCLUDED.commit_sha`, [projectId, tag, sha, id])
      if (p.signed !== false) {
        await db.pool.query(
          `INSERT INTO release_reports (scan_id, project_id, tag, commit_sha, report, report_sha256, status, signature, key_fingerprint, signed_at)
           VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, 'signed', $6, $7, now())`,
          [id, projectId, tag, sha, 'c'.repeat(64), `${'A'.repeat(86)}==`, fingerprint])
      }
    }
    return id
  }

  /** Simule le helper root : signe la PAE de chaque demande sign-attestation en attente. */
  async function helperSigns(opts: { fail?: string } = {}) {
    const r = await db.pool.query<{ id: string, content: string, sha256: string }>(
      `SELECT id::text, params ->> 'content_b64' AS content, params ->> 'sha256' AS sha256 FROM helper_requests
        WHERE type = 'sign-attestation' AND status = 'pending'`)
    for (const x of r.rows) {
      const bytes = Buffer.from(x.content, 'base64')
      expect(createHash('sha256').update(bytes).digest('hex')).toBe(x.sha256)
      if (opts.fail) {
        await db.pool.query(`UPDATE helper_requests SET status = 'error', code = $2, finished_at = now() WHERE id = $1`, [x.id, opts.fail])
        continue
      }
      const signature = edSign(null, pae(PAYLOAD_TYPE, bytes), keys.privateKey).toString('base64')
      await db.pool.query(`UPDATE helper_requests SET status = 'ok', code = 'OK', output = $2, finished_at = now() WHERE id = $1`,
        [x.id, JSON.stringify({ kind: 'attestation', sha256: x.sha256, subject_digest: 'x', payload_type: PAYLOAD_TYPE, signature, key_fingerprint: fingerprint })])
    }
    return r.rowCount ?? 0
  }

  /** Clé publique de l'appliance telle que le helper la publie (état hors ligne). */
  async function publishKey(raw: Buffer) {
    await writeFile(join(dir, 'offline-status.json'), JSON.stringify({
      version: 1, updated_at: '2026-11-25T10:00:00Z',
      appliance_key: { public_key: raw.toString('base64'), fingerprint: createHash('sha256').update(raw).digest('hex') },
      trusted_keys: [], bundles: [], last_import: null, mirror: null, publication: null,
      schedule: { enabled: false, every_days: 7, keep: 3, modules: [], last_run_at: null }, dtrack: null,
    }))
  }

  const runs = async (scanId: string) => (await listDeployments(db.pool, { scanId })).sort((a, b) => a.kind.localeCompare(b.kind))
  const auditCount = async (action: string) => Number((await db.pool.query<{ n: string }>('SELECT count(*) AS n FROM audit_log WHERE action = $1', [action])).rows[0]!.n)

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-deploy-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    await mkdir(join(dir, 'tmp'))
    await mkdir(join(dir, 'incoming'))
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_REQUESTS_DIR: dir,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
      NUXT_STATE_FILE: join(dir, 'absent-photo.json'),
      NUXT_OFFLINE_STATUS_FILE: join(dir, 'offline-status.json'),
    }))
    await publishKey(rawPub)
    setConsoleUrl(CONSOLE)
    setForgeRetryDelays([1, 1])
    forge = fakeForgejo()
    setForgeTransport(forge.handler)
    reg = fakeRegistry(REG, { token: fakeToken() })
    setRegistryTransport(reg.transport)
    const cred = await encryptSecret(db.pool, { kind: 'token', value: fakeToken() })
    const f = await db.pool.query<{ id: string }>(`INSERT INTO forges (kind, name, base_url, credential_id) VALUES ('forgejo', 'Forge', $1, $2) RETURNING id::text`, [`https://${FORGE}`, cred])
    const p = await db.pool.query<{ id: string }>(
      `INSERT INTO projects (slug, name, source_kind, profile_id, gate_id, forge_id, repo_full_name)
       VALUES ('app', 'App', 'archive', (SELECT id FROM profiles WHERE slug = 'rapide'), (SELECT id FROM gates WHERE slug = 'defaut'), $1, 'equipe/app')
       RETURNING id::text`, [f.rows[0]!.id])
    projectId = p.rows[0]!.id
    const u = await db.pool.query<{ id: number }>(`INSERT INTO users (username, role, password_hash) VALUES ('admin', 'admin', $1) RETURNING id`, [await hashPassword('x-long-password-for-tests')])
    adminId = u.rows[0]!.id
  })

  afterAll(async () => {
    setConsoleUrl()
    setForgeRetryDelays()
    setForgeTransport()
    setRegistryTransport()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  beforeEach(() => {
    forge.calls.length = 0
    reg.log.length = 0
  })

  it('cibles : création tracée, validation, fusion automatique réservée au GitOps', async () => {
    await expect(createTarget(db.pool, projectId, { kind: 'gitops-pr', environment: 'production', on_trigger: 'release', enabled: true, config: { repo: 'equipe/deploiement', files: [{ path: '../x', image: `${REG}/valide/app` }] } } as never, admin()))
      .rejects.toThrow()
    const reg1 = await createTarget(db.pool, projectId, {
      kind: 'registry-promotion', environment: 'production', on_trigger: 'release', enabled: true,
      config: { source: `${REG}/candidat/app`, destination: `${REG}/valide/app` },
    } as never, admin())
    const git = await createTarget(db.pool, projectId, {
      kind: 'gitops-pr', environment: 'production', on_trigger: 'release', enabled: true,
      config: { repo: 'equipe/deploiement', files: [{ path: 'apps/app/deploiement.yaml', image: `${REG}/valide/app` }] },
    } as never, admin())
    const cd = await createTarget(db.pool, projectId, {
      kind: 'cd-trigger', environment: 'production', on_trigger: 'release', enabled: true,
      config: { provider: 'forge', workflow: 'deploy.yml', inputs: ['scanoria_report', 'scanoria_commit', 'scanoria_tag', 'scanoria_image'] },
    } as never, admin())
    expect([reg1, git, cd].every(t => t.id)).toBe(true)
    await expect(updateTarget(db.pool, (await getTarget(db.pool, cd.id))!, { auto_merge: true }, admin())).rejects.toThrow()
    const t = await listTargets(db.pool, projectId)
    expect(t).toHaveLength(3)
    expect(t.find(x => x.kind === 'registry-promotion')?.credential_hint ?? null).toBeNull()
    expect(await auditCount('deploy.target.create')).toBe(3)
  })

  it('verdict défavorable : refus enregistré, rien ne part', async () => {
    const s = await scan({ verdict: 'failed' })
    await deployPass(db.pool)
    const r = await runs(s)
    expect(r).toHaveLength(3)
    expect(r.every(x => x.status === 'refused' && x.refused_reason === 'verdict-not-passed')).toBe(true)
    expect(forge.calls.filter(c => c.method !== 'GET')).toHaveLength(0)
    expect(reg.log.filter(l => !l.startsWith('GET') && !l.startsWith('HEAD'))).toHaveLength(0)
    await deployPass(db.pool)
    expect(await runs(s)).toHaveLength(3)
  })

  it('release favorable : promotion par empreinte, attestation signée, PR GitOps, CD déclenchée une fois puis suivie', async () => {
    const digest = reg.addIndex('candidat/app', 'v1.2.0')
    forge.files.set('apps/app/deploiement.yaml', `image: ${REG}/valide/app:v1.1.0@sha256:${'0'.repeat(64)}\nreplicas: 2\n`)
    const s = await scan({ verdict: 'passed' })

    // Passe 1 : empreinte résolue, demande de signature déposée, rien d'autre.
    await deployPass(db.pool)
    let r = await runs(s)
    expect(r.find(x => x.kind === 'registry-promotion')).toMatchObject({ status: 'running', external_id: digest })
    expect(r.filter(x => x.kind !== 'registry-promotion').every(x => x.status === 'pending')).toBe(true)
    expect(forge.calls).toHaveLength(0)
    expect(await helperSigns()).toBe(1)

    // Passe 2 : copie, attestation poussée, PR ouverte, CD déclenchée.
    await deployPass(db.pool)
    r = await runs(s)
    expect(r.find(x => x.kind === 'registry-promotion')?.status).toBe('succeeded')
    expect(reg.manifests.get('valide/app')?.has(digest)).toBe(true)
    expect(reg.manifests.get('valide/app')?.has(`${digest.replace(':', '-')}.att`)).toBe(true)
    const att = await db.pool.query<{ status: string, envelope: unknown, subject_name: string }>('SELECT status, envelope, subject_name FROM attestations WHERE scan_id = $1', [s])
    expect(att.rows[0]).toMatchObject({ status: 'pushed', subject_name: `${REG}/valide/app` })
    const v = verifyEnvelope(att.rows[0]!.envelope as never, rawPub, digest)
    expect(v?.statement.predicateType).toBe(PREDICATE_TYPE)
    expect(v?.statement.predicate.verdict).toBe('passed')
    expect(v?.statement.predicate.report_sha256).toBe('c'.repeat(64))

    const gitops = r.find(x => x.kind === 'gitops-pr')!
    expect(gitops).toMatchObject({ status: 'succeeded', external_id: '7' })
    const commit = forge.calls.find(c => c.path.endsWith('/contents') && c.method === 'POST')!
    const written = Buffer.from((commit.body as { files: { content: string }[] }).files[0]!.content, 'base64').toString()
    expect(written).toBe(`image: ${REG}/valide/app:v1.1.0@${digest}\nreplicas: 2\n`)
    expect((commit.body as { new_branch: string }).new_branch).toMatch(/^scanoria\/promote\/production-[0-9a-f]{8}$/)
    expect(forge.calls.some(c => c.path.includes('/merge'))).toBe(false)

    const cd = r.find(x => x.kind === 'cd-trigger')!
    expect(cd).toMatchObject({ status: 'running', external_id: '42' })
    const dispatch = forge.calls.filter(c => c.path.endsWith('/dispatches'))
    expect(dispatch).toHaveLength(1)
    expect((dispatch[0]!.body as { ref: string, inputs: Record<string, string> })).toMatchObject({
      ref: 'v1.2.0',
      inputs: { scanoria_report: `${CONSOLE}/scans/${s}`, scanoria_tag: 'v1.2.0', scanoria_image: `${REG}/valide/app@${digest}` },
    })

    // Passe 3 : toujours en cours, aucun second déclenchement.
    forge.calls.length = 0
    await deployPass(db.pool)
    expect(forge.calls.filter(c => c.path.endsWith('/dispatches'))).toHaveLength(0)
    forge.state.runStatus = 'completed'
    forge.state.runConclusion = 'success'
    await deployPass(db.pool)
    expect((await runs(s)).find(x => x.kind === 'cd-trigger')?.status).toBe('succeeded')
    expect(await auditCount('deploy.cd.trigger')).toBe(1)
    expect(await auditCount('deploy.registry.promote')).toBe(1)
    expect(await auditCount('deploy.gitops.pr')).toBe(1)

    // Vue de la chaîne : attestations sans enveloppe.
    const chain = await projectChain(db.pool, projectId)
    const rel = chain.releases.find(x => x.scan_id === s)!
    expect(rel.deployments).toHaveLength(3)
    expect(JSON.stringify(rel.attestations)).not.toContain('signatures')
  })

  it('échec de signature : la chaîne s\'arrête net (E_DEPLOY_PREVIOUS)', async () => {
    reg.addImage('candidat/app', 'v1.3.0')
    const s = await scan({ verdict: 'passed', tag: 'v1.3.0', ref: 'refs/tags/v1.3.0' })
    await deployPass(db.pool)
    await helperSigns({ fail: 'E_ATTEST_KEY' })
    await deployPass(db.pool)
    const r = await runs(s)
    expect(r.find(x => x.kind === 'registry-promotion')).toMatchObject({ status: 'failed' })
    expect(r.find(x => x.kind === 'registry-promotion')?.error).toContain('E_ATTEST_KEY')
    expect(r.filter(x => x.kind !== 'registry-promotion').map(x => [x.status, x.error])).toEqual([['failed', 'E_DEPLOY_PREVIOUS'], ['failed', 'E_DEPLOY_PREVIOUS']])
    expect(forge.calls.filter(c => c.method !== 'GET')).toHaveLength(0)
  })

  it('étiquette candidate repoussée avec l\'image d\'un autre commit : jamais promue', async () => {
    reg.addImage('candidat/app', 'v1.3.1', { 'org.opencontainers.image.revision': 'f'.repeat(40) })
    const s = await scan({ verdict: 'passed', tag: 'v1.3.1', ref: 'refs/tags/v1.3.1' })
    await deployPass(db.pool)
    const r = await runs(s)
    expect(r.find(x => x.kind === 'registry-promotion')).toMatchObject({ status: 'failed', error: 'E_DEPLOY_REVISION' })
    expect(r.filter(x => x.kind !== 'registry-promotion').every(x => x.error === 'E_DEPLOY_PREVIOUS')).toBe(true)
    expect(reg.manifests.get('valide/app')?.has('v1.3.1') ?? false).toBe(false)
    expect(await auditCount('deploy.registry.revision')).toBe(1)
  })

  it('signature rendue qui ne vérifie pas avec la clé publiée de l\'appliance : refusée', async () => {
    const other = (generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }) as Buffer).subarray(-32)
    await publishKey(other)
    try {
      reg.addImage('candidat/app', 'v1.3.2')
      const s = await scan({ verdict: 'passed', tag: 'v1.3.2', ref: 'refs/tags/v1.3.2' })
      await deployPass(db.pool)
      await helperSigns()
      await deployPass(db.pool)
      const r = await runs(s)
      expect(r.find(x => x.kind === 'registry-promotion')?.error).toContain('E_ATTEST_KEY')
      expect(reg.manifests.get('valide/app')?.has('v1.3.2') ?? false).toBe(false)
    }
    finally {
      await publishKey(rawPub)
    }
  })

  it('rapport de release non signé : attente, sans aucune action', async () => {
    const s = await scan({ verdict: 'passed', tag: 'v1.4.0', ref: 'refs/tags/v1.4.0', signed: false })
    await deployPass(db.pool)
    expect(await runs(s)).toHaveLength(0)
  })

  it('cible désactivée : refus tracé', async () => {
    const t = (await listTargets(db.pool, projectId)).find(x => x.kind === 'cd-trigger')!
    await updateTarget(db.pool, (await getTarget(db.pool, t.id))!, { enabled: false }, admin())
    reg.addImage('candidat/app', 'v1.5.0')
    const s = await scan({ verdict: 'passed', tag: 'v1.5.0', ref: 'refs/tags/v1.5.0' })
    await deployPass(db.pool, { scanId: s })
    expect((await runs(s)).find(x => x.kind === 'cd-trigger')).toMatchObject({ status: 'refused', refused_reason: 'target-disabled' })
    // Hors sujet pour la suite : les autres exécutions de cette analyse sont closes.
    await db.pool.query(`UPDATE deployments SET status = 'failed', error = 'test', finished_at = now() WHERE scan_id = $1 AND status IN ('pending', 'running')`, [s])
    await updateTarget(db.pool, (await getTarget(db.pool, t.id))!, { enabled: true }, admin())
  })

  it('auto_merge GitOps : fusion NATIVE de la forge activée, jamais un merge direct', async () => {
    const t = (await listTargets(db.pool, projectId)).find(x => x.kind === 'gitops-pr')!
    await updateTarget(db.pool, (await getTarget(db.pool, t.id))!, { auto_merge: true }, admin())
    const row = await db.pool.query<{ auto_merge_by: number }>('SELECT auto_merge_by FROM deploy_targets WHERE id = $1', [t.id])
    expect(row.rows[0]!.auto_merge_by).toBe(adminId)
    const digest = reg.addImage('candidat/app', 'v1.6.0')
    forge.files.set('apps/app/deploiement.yaml', `image: ${REG}/valide/app@sha256:${'1'.repeat(64)}\n`)
    const s = await scan({ verdict: 'passed', tag: 'v1.6.0', ref: 'refs/tags/v1.6.0' })
    await deployPass(db.pool)
    await helperSigns()
    await deployPass(db.pool)
    const merge = forge.calls.filter(c => c.path.endsWith('/pulls/7/merge'))
    expect(merge).toHaveLength(1)
    expect(merge[0]!.body).toMatchObject({ merge_when_checks_succeed: true, head_commit_id: 'c'.repeat(40) })
    expect((await runs(s)).find(x => x.kind === 'registry-promotion')?.external_id).toBe(digest)
    await updateTarget(db.pool, (await getTarget(db.pool, t.id))!, { auto_merge: false }, admin())
  })

  it('déclenchement refusé par la forge : échec avec code, jamais rejoué', async () => {
    forge.state.dispatchFails = true
    reg.addImage('candidat/app', 'v1.7.0')
    forge.files.set('apps/app/deploiement.yaml', `image: ${REG}/valide/app@sha256:${'2'.repeat(64)}\n`)
    const s = await scan({ verdict: 'passed', tag: 'v1.7.0', ref: 'refs/tags/v1.7.0' })
    await deployPass(db.pool)
    await helperSigns()
    await deployPass(db.pool)
    await deployPass(db.pool)
    const cd = (await runs(s)).find(x => x.kind === 'cd-trigger')!
    expect(cd.status).toBe('failed')
    expect(cd.error).toMatch(/^E_FORGE_/)
    expect(forge.calls.filter(c => c.path.endsWith('/dispatches'))).toHaveLength(1)
    forge.state.dispatchFails = false
  })

  it('verdict changé après coup : les exécutions en cours échouent sans action', async () => {
    reg.addImage('candidat/app', 'v1.8.0')
    const s = await scan({ verdict: 'passed', tag: 'v1.8.0', ref: 'refs/tags/v1.8.0' })
    await deployPass(db.pool)
    await db.pool.query(`UPDATE scans SET verdict = 'failed' WHERE id = $1`, [s])
    await helperSigns()
    await deployPass(db.pool)
    const r = await runs(s)
    expect(r.every(x => x.status === 'failed' && x.error === 'verdict-not-passed')).toBe(true)
    expect(forge.calls.filter(c => c.method !== 'GET')).toHaveLength(0)
  })

  it('cible de branche : seules les analyses de la branche configurée comptent', async () => {
    await createTarget(db.pool, projectId, {
      kind: 'cd-trigger', environment: 'recette', on_trigger: 'branch', enabled: true,
      config: { provider: 'forge', workflow: 'deploy.yml', branch: 'main', inputs: ['scanoria_commit'] },
    } as never, admin())
    const other = await scan({ verdict: 'passed', trigger: 'commit', ref: 'refs/heads/dev', tag: null })
    const main = await scan({ verdict: 'passed', trigger: 'commit', ref: 'refs/heads/main', tag: null })
    await deployPass(db.pool)
    expect(await runs(other)).toHaveLength(0)
    const r = await runs(main)
    expect(r).toHaveLength(1)
    expect(r[0]).toMatchObject({ environment: 'recette', status: 'running', external_id: '42' })
    const d = forge.calls.find(c => c.path.endsWith('/dispatches'))!
    expect((d.body as { ref: string }).ref).toBe('main')
  })

  it('proposition J11 : workflow manuel qui déclare scanoria_report', async () => {
    const yaml = 'on:\n  workflow_dispatch:\n    inputs:\n      scanoria_report: { required: true }\n      scanoria_commit: { required: true }\n'
    const prev = forge.handler
    setForgeTransport(async (url, init) => {
      const p = new URL(url).pathname
      const ok = (d: unknown) => new Response(typeof d === 'string' ? d : JSON.stringify(d), { status: 200 })
      if (p === '/api/v1/repos/equipe/app') return ok({ full_name: 'equipe/app', clone_url: `https://${FORGE}/equipe/app.git`, default_branch: 'main' })
      if (p === '/api/v1/repos/equipe/app/git/trees/main') return ok({ tree: [{ path: '.forgejo/workflows/livraison.yml', type: 'blob' }, { path: '.forgejo/workflows/ci.yml', type: 'blob' }] })
      if (p === '/api/v1/repos/equipe/app/raw/.forgejo/workflows/livraison.yml') return ok(yaml)
      if (p === '/api/v1/repos/equipe/app/raw/.forgejo/workflows/ci.yml') return ok('on: [push]\n')
      return prev(url, init)
    })
    try {
      const props = await proposeTargets(db.pool, projectId)
      expect(props).toHaveLength(1)
      expect(props[0]).toMatchObject({ kind: 'cd-trigger', environment: 'livraison', reason: { workflow: 'livraison.yml', inputs: ['scanoria_report', 'scanoria_commit'] } })
    }
    finally {
      setForgeTransport(forge.handler)
    }
  })

  describe('chaîne autonome (J16)', () => {
    beforeAll(async () => {
      await db.pool.query('UPDATE projects SET autonomous_chain = true WHERE id = $1', [projectId])
    })

    it('marqueur présent : fusion automatique native activée, une seule fois par analyse', async () => {
      forge.state.prBody = 'Correctif.\n\n/scanoria auto-merge\n'
      const s = await scan({ verdict: 'passed', trigger: 'webhook', ref: 'refs/pull/12/head', pr: 12 })
      await deployPass(db.pool)
      await deployPass(db.pool)
      const merges = forge.calls.filter(c => c.path.endsWith('/pulls/12/merge'))
      expect(merges).toHaveLength(1)
      expect(merges[0]!.body).toMatchObject({ head_commit_id: forge.state.heads.get(12) })
      const a = await db.pool.query<{ details: { result: string } }>('SELECT details FROM audit_log WHERE action = $1 AND target_id = $2', [AUTOMERGE_ACTION, s])
      expect(a.rows.map(x => x.details.result)).toEqual(['enabled'])
      expect(await runs(s)).toHaveLength(0)
    })

    it('nouveau commit poussé depuis l\'analyse : aucune fusion, résultat « stale »', async () => {
      forge.state.prBody = '/scanoria auto-merge'
      const s = await scan({ verdict: 'passed', trigger: 'webhook', ref: 'refs/pull/16/head', pr: 16 })
      forge.state.heads.set(16, 'f'.repeat(40))
      await deployPass(db.pool)
      expect(forge.calls.some(c => c.path.endsWith('/pulls/16/merge'))).toBe(false)
      const a = await db.pool.query<{ details: { result: string } }>('SELECT details FROM audit_log WHERE action = $1 AND target_id = $2', [AUTOMERGE_ACTION, s])
      expect(a.rows.map(x => x.details.result)).toEqual(['stale'])
    })

    it('sans marqueur, PR fermée ou verdict défavorable : rien', async () => {
      forge.state.prBody = 'Pas de demande.'
      const s1 = await scan({ verdict: 'passed', trigger: 'webhook', ref: 'refs/pull/13/head', pr: 13 })
      const s2 = await scan({ verdict: 'failed', trigger: 'webhook', ref: 'refs/pull/14/head', pr: 14 })
      await deployPass(db.pool)
      forge.state.prBody = '/scanoria auto-merge'
      forge.state.prOpen = false
      const s3 = await scan({ verdict: 'passed', trigger: 'webhook', ref: 'refs/pull/15/head', pr: 15 })
      await deployPass(db.pool)
      forge.state.prOpen = true
      expect(forge.calls.some(c => c.path.includes('/merge'))).toBe(false)
      const res = async (id: string) => (await db.pool.query<{ details: { result: string } }>('SELECT details FROM audit_log WHERE action = $1 AND target_id = $2', [AUTOMERGE_ACTION, id])).rows.map(x => x.details.result)
      expect(await res(s1)).toEqual(['not-requested'])
      expect(await res(s2)).toEqual([])
      expect(await res(s3)).toEqual(['closed'])
    })
  })

  it('écouteur : enregistré une seule fois, déclenche une passe sur l\'analyse', async () => {
    const handlers: ((e: { scanId: string, projectId: string, verdict: string | null, reportSha256: string | null }) => unknown)[] = []
    const on = (h: (typeof handlers)[number]) => handlers.push(h)
    registerDeployListeners(on, () => db.pool)
    registerDeployListeners(on, () => db.pool)
    expect(handlers).toHaveLength(1)
    const s = await scan({ verdict: 'failed', tag: 'v2.0.0', ref: 'refs/tags/v2.0.0' })
    await handlers[0]!({ scanId: s, projectId, verdict: 'failed', reportSha256: null })
    expect((await runs(s)).every(x => x.status === 'refused')).toBe(true)
  })
})
