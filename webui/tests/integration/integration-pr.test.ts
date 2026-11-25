// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J2 et J3 (0.8, chantier C) contre PostgreSQL et une fausse forge en
// écriture (Forgejo, GitHub, GitLab) : une seule PR d'intégration par dépôt,
// avec le modèle de la CI détectée et le mode du projet ; jamais de fusion ;
// état suivi ; étape Scanoria déjà présente → aucune PR ; protection proposée,
// appliquée seulement après la décision d'un administrateur humain (ajout de
// contextes à la règle existante), droit manquant signalé ; case J16 auditée.

import { randomBytes } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { startFakeCi, type FakeCi, type FakeRequest } from '../helpers/fake-ci'
import { loadConfig, setConfig } from '../../server/utils/config'
import { encryptSecret } from '../../server/utils/secrets'
import { createUser } from '../../server/utils/users'
import { setConsoleUrl } from '../../server/forges/context'
import { setForgeRetryDelays } from '../../server/forges/http'
import { createProject } from '../../server/projects/service'
import type { CiWorkflow, Detection } from '../../server/projects/detect'
import {
  chooseCi, decideProtection, listIntegrationRequests, missingPermission, proposeIntegration, requestProtection, runCiIntegration, setAutonomousChain,
} from '../../server/ci/integration'
import { clientSha256 } from '../../server/ci/templates'

const TEMPLATES = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/ci-templates', import.meta.url))
const CLIENT = fileURLToPath(new URL('../../../src/rootfs/usr/share/scanoria/client/scanoria-scan', import.meta.url))
const CONSOLE = 'https://analyse.exemple.test'

interface RepoFiles { files: Record<string, string>, prs: Map<number, { state: string, merged: boolean, body: string, title: string, head: string }>, protection: string[] | null, pushed: Record<string, string> }

describe.skipIf(!DATABASE_URL)('PR d’intégration et protection (J2, PostgreSQL)', () => {
  let db: TestDatabase
  let dir: string
  let fake: FakeCi
  let admin: { userId: number, username: string }
  const repos = new Map<string, RepoFiles>()
  let deny = new Set<string>()
  const forges: Record<'forgejo' | 'github' | 'gitlab', string> = { forgejo: '', github: '', gitlab: '' }

  const repo = (name: string, files: Record<string, string> = {}): RepoFiles => {
    const r = { files, prs: new Map(), protection: null, pushed: {} }
    repos.set(name, r)
    return r
  }
  const writes = () => fake.requests.filter(r => r.method !== 'GET')
  const decode = (s: string) => Buffer.from(s, 'base64').toString('utf8')

  function detection(ci: CiWorkflow[]): Detection {
    return {
      version: 1, analyzed_at: '2026-11-25T10:00:00Z', ref: 'main', commit: null, truncated: false, files: 3, languages: [], language_files: {},
      package_managers: [], missing_lockfiles: [], containers: [], iac: { terraform: false, kubernetes: false, helm: false, ansible: false },
      ci, shell_scripts: 0, license: null, categories: [], profile: 'complet', pr_profile: 'rapide', modules: [], coverage_gaps: [],
    } as unknown as Detection
  }

  async function project(kind: keyof typeof forges, name: string, ci: CiWorkflow[], extra: { mode?: 'pull' | 'push' | 'off' } = {}) {
    const p = await createProject(db.pool, {
      name, sourceKind: 'git', forgeId: forges[kind], repoFullName: name, repoUrl: `https://${kind}.exemple.test/${name}.git`, defaultBranch: 'main',
      detection: detection(ci),
    })
    if (extra.mode) await db.pool.query('UPDATE projects SET release_mode = $2 WHERE id = $1', [p.id, extra.mode])
    return p.id
  }

  /** Forgejo (API v1), GitHub (REST v3) et GitLab (API v4), réduits à ce que J2 écrit et lit. */
  function forgeHandler(req: FakeRequest): { status: number, body?: unknown } | null {
    const u = new URL(req.url)
    if (deny.has(`${req.method} ${u.pathname}`)) return { status: 403, body: { message: 'forbidden' } }
    let m = /^\/api\/v1\/repos\/([^/]+\/[^/]+)\/(.*)$/.exec(u.pathname) ?? /^\/repos\/([^/]+\/[^/]+)\/(.*)$/.exec(u.pathname)
    if (m) {
      const r = repos.get(decodeURIComponent(m[1]!))
      const rest = m[2]!
      if (!r) return { status: 404 }
      const raw = /^raw\/(.+)$/.exec(rest) ?? (req.method === 'GET' ? /^contents\/(.+)$/.exec(rest) : null)
      if (raw && req.method === 'GET') {
        const f = r.files[decodeURIComponent(raw[1]!)]
        return f === undefined ? { status: 404 } : { status: 200, body: f }
      }
      const body = req.body as Record<string, unknown>
      if (rest === 'contents' && req.method === 'POST') {
        for (const f of body.files as { path: string, content: string, operation: string }[]) r.pushed[f.path] = decode(f.content)
        return { status: 201, body: {} }
      }
      if (rest === 'git/ref/heads/main') return { status: 200, body: { object: { sha: 'a'.repeat(40) } } }
      if (rest === 'git/refs' && req.method === 'POST') return { status: 201, body: {} }
      const put = /^contents\/(.+)$/.exec(rest)
      if (put && req.method === 'PUT') {
        r.pushed[decodeURIComponent(put[1]!)] = decode(body.content as string)
        return { status: 201, body: {} }
      }
      if (rest === 'pulls' && req.method === 'POST') {
        const n = r.prs.size + 1
        r.prs.set(n, { state: 'open', merged: false, body: body.body as string, title: body.title as string, head: body.head as string })
        return { status: 201, body: { number: n, html_url: `https://forge.exemple.test/${m[1]}/pulls/${n}` } }
      }
      const pr = /^pulls\/(\d+)$/.exec(rest)
      if (pr && req.method === 'GET') {
        const p = r.prs.get(Number(pr[1]))
        return p ? { status: 200, body: { state: p.state, merged: p.merged } } : { status: 404 }
      }
      if (rest === 'branch_protections' && req.method === 'GET') return { status: 200, body: r.protection ? [{ rule_name: 'main', status_check_contexts: r.protection }] : [] }
      if (rest === 'branch_protections' && req.method === 'POST') {
        r.protection = body.status_check_contexts as string[]
        return { status: 201, body: {} }
      }
      if (rest === 'branch_protections/main' && req.method === 'PATCH') {
        r.protection = body.status_check_contexts as string[]
        return { status: 200, body: {} }
      }
      if (rest === 'branches/main/protection' && req.method === 'GET') return r.protection ? { status: 200, body: {} } : { status: 404 }
      if (rest === 'branches/main/protection' && req.method === 'PUT') {
        r.protection = (body.required_status_checks as { contexts: string[] }).contexts
        return { status: 200, body: {} }
      }
      if (rest === 'branches/main/protection/required_status_checks/contexts' && req.method === 'POST') {
        r.protection = [...new Set([...(r.protection ?? []), ...(body.contexts as string[])])]
        return { status: 200, body: r.protection }
      }
      return null
    }
    m = /^\/api\/v4\/projects\/([^/]+)(\/.*)?$/.exec(u.pathname)
    if (m) {
      const r = repos.get(decodeURIComponent(m[1]!))
      const rest = m[2] ?? ''
      if (!r) return { status: 404 }
      const body = req.body as Record<string, unknown>
      const file = /^\/repository\/files\/(.+)\/raw$/.exec(rest)
      if (file) {
        const f = r.files[decodeURIComponent(file[1]!)]
        return f === undefined ? { status: 404 } : { status: 200, body: f }
      }
      if (rest === '/repository/commits' && req.method === 'POST') {
        for (const a of body.actions as { file_path: string, content: string, action: string }[]) r.pushed[`${a.action}:${a.file_path}`] = a.content
        return { status: 201, body: {} }
      }
      if (rest === '/merge_requests' && req.method === 'POST') {
        const n = r.prs.size + 1
        r.prs.set(n, { state: 'opened', merged: false, body: body.description as string, title: body.title as string, head: body.source_branch as string })
        return { status: 201, body: { iid: n, web_url: `https://gitlab.exemple.test/${decodeURIComponent(m[1]!)}/-/merge_requests/${n}` } }
      }
      const mr = /^\/merge_requests\/(\d+)$/.exec(rest)
      if (mr) return { status: 200, body: { state: r.prs.get(Number(mr[1]))?.state ?? 'closed' } }
      if (rest === '' && req.method === 'PUT') {
        r.protection = body.only_allow_merge_if_pipeline_succeeds ? ['pipeline'] : null
        return { status: 200, body: {} }
      }
    }
    return null
  }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-integration-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    process.env.NUXT_CI_TEMPLATES_DIR = TEMPLATES
    process.env.NUXT_SCANORIA_SCAN_CLIENT = CLIENT
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    setConsoleUrl(CONSOLE)
    setForgeRetryDelays([1, 1])
    fake = startFakeCi()
    fake.handlers.push(forgeHandler)
    for (const kind of ['forgejo', 'github', 'gitlab'] as const) {
      const cred = await encryptSecret(db.pool, { kind: 'token', value: randomBytes(20).toString('hex'), username: 'scanoria-bot', createdBy: null })
      const base = kind === 'github' ? 'https://github.com' : `https://${kind}.exemple.test`
      forges[kind] = (await db.pool.query<{ id: string }>(
        `INSERT INTO forges (kind, name, base_url, credential_id, discovery) VALUES ($1, $1, $2, $3, false) RETURNING id::text`, [kind, base, cred])).rows[0]!.id
    }
    const u = await createUser(db.pool, { username: 'admin', role: 'admin', password: 'admin-long-password' })
    admin = { userId: Number(u.id), username: 'admin' }
  })

  afterAll(async () => {
    fake?.restore()
    setConsoleUrl()
    setForgeRetryDelays()
    delete process.env.NUXT_CI_TEMPLATES_DIR
    delete process.env.NUXT_SCANORIA_SCAN_CLIENT
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  it('choix de la CI : forge, dossier de workflows déjà lu, Jenkinsfile seul', () => {
    expect(chooseCi('github', [])).toEqual({ ci: 'github', dir: '.github' })
    expect(chooseCi('gitlab', [{ kind: 'gitlab-ci', path: '.gitlab-ci.yml' }])).toEqual({ ci: 'gitlab', dir: '.gitlab' })
    expect(chooseCi('forgejo', [])).toEqual({ ci: 'forgejo', dir: '.forgejo' })
    expect(chooseCi('forgejo', [{ kind: 'github-actions', path: '.github/workflows/ci.yml' }])).toEqual({ ci: 'forgejo', dir: '.github' })
    expect(chooseCi('forgejo', [{ kind: 'forgejo-actions', path: '.gitea/workflows/ci.yml' }])).toEqual({ ci: 'forgejo', dir: '.gitea' })
    expect(chooseCi('forgejo', [{ kind: 'forgejo-actions', path: '.forgejo/workflows/a.yml' }, { kind: 'github-actions', path: '.github/workflows/b.yml' }]).dir).toBe('.forgejo')
    expect(chooseCi('forgejo', [{ kind: 'jenkins', path: 'Jenkinsfile' }])).toEqual({ ci: 'jenkins', dir: 'ci/scanoria' })
    expect(chooseCi('github', [{ kind: 'jenkins', path: 'Jenkinsfile' }, { kind: 'github-actions', path: '.github/workflows/ci.yml' }]).ci).toBe('github')
    expect(missingPermission('github', 'ci-pr')).toContain('workflows: write')
    expect(missingPermission('forgejo', 'branch-protection')).toContain('admin')
    expect(missingPermission('gitlab', 'branch-protection')).toContain('Maintainer')
  })

  it('Forgejo, mode poussé : une PR, workflow rendu pour le projet, étape commune, empreinte du client ; jamais de fusion', async () => {
    const r = repo('equipe/app', { '.forgejo/workflows/ci.yml': 'on: push\njobs: {}\n' })
    const id = await project('forgejo', 'equipe/app', [{ kind: 'forgejo-actions', path: '.forgejo/workflows/ci.yml' }], { mode: 'push' })
    const out = await proposeIntegration(db.pool, id)
    expect(out).toMatchObject({ outcome: 'opened', number: 1 })
    const wf = r.pushed['.forgejo/workflows/scanoria.yml']!
    expect(wf).toContain(`SCANORIA_URL: ${CONSOLE}`)
    expect(wf).toContain(`SCANORIA_PROJECT: ${id}`)
    expect(wf).toContain('SCANORIA_MODE: push')
    expect(wf).toContain(`SCANORIA_CLIENT_SHA256: "${await clientSha256()}"`)
    expect(wf).toContain('enable-openid-connect: true')
    expect(wf).toContain('  pull_request:')
    expect(wf).not.toContain('00000000-0000-4000-8000-000000000000')
    expect(r.pushed['.forgejo/scanoria/scanoria-ci.sh']).toMatch(/^#!\/bin\/sh/)
    const pr = r.prs.get(1)!
    expect(pr.head).toMatch(/^scanoria\/integration-[0-9a-f]{8}$/)
    expect(pr.body).toContain('ne fusionne jamais')
    // Aucune écriture de fusion vers la forge.
    expect(writes().some(w => /merge/.test(w.url))).toBe(false)
    // Une seule PR, même relancée (passe périodique ou appel sans force).
    expect((await proposeIntegration(db.pool, id)).outcome).toBe('exists')
    expect((await proposeIntegration(db.pool, id, { force: true })).outcome).toBe('exists')
    expect(r.prs.size).toBe(1)
    const reqs = await listIntegrationRequests(db.pool, id)
    expect(reqs.map(x => `${x.kind}:${x.state}`).sort()).toEqual(['branch-protection:proposed', 'ci-pr:open'])
    const audit = (await db.pool.query(`SELECT outcome FROM audit_log WHERE action = 'integration.ci-pr' AND target_id = $1`, [id])).rows
    expect(audit).toEqual([{ outcome: 'success' }])
  })

  it('état suivi : PR fusionnée puis plus aucune nouvelle PR ; PR fermée → réouverture manuelle seulement', async () => {
    const r = repos.get('equipe/app')!
    r.prs.get(1)!.merged = true
    r.prs.get(1)!.state = 'closed'
    const out = await runCiIntegration(db.pool)
    expect(out.synced).toBeGreaterThanOrEqual(1)
    const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/app'`)).rows[0]!.id
    expect((await listIntegrationRequests(db.pool, id)).find(x => x.kind === 'ci-pr')?.state).toBe('merged')
    expect((await db.pool.query(`SELECT 1 FROM audit_log WHERE action = 'integration.pr-merged'`)).rowCount).toBe(1)

    const r2 = repo('equipe/ferme')
    const id2 = await project('forgejo', 'equipe/ferme', [])
    expect((await proposeIntegration(db.pool, id2)).outcome).toBe('opened')
    r2.prs.get(1)!.state = 'closed'
    await runCiIntegration(db.pool)
    expect((await listIntegrationRequests(db.pool, id2)).find(x => x.kind === 'ci-pr')?.state).toBe('closed')
    // La passe périodique ne rouvre jamais ; un opérateur le peut.
    await runCiIntegration(db.pool)
    expect(r2.prs.size).toBe(1)
    expect((await proposeIntegration(db.pool, id2, { force: true })).outcome).toBe('opened')
    expect(r2.prs.size).toBe(2)
  })

  it('étape Scanoria déjà présente : aucune PR ; détection absente : en attente', async () => {
    repo('equipe/deja', { '.forgejo/workflows/ci.yml': 'steps:\n  - run: scanoria-scan --wait\n' })
    const id = await project('forgejo', 'equipe/deja', [{ kind: 'forgejo-actions', path: '.forgejo/workflows/ci.yml' }])
    expect((await proposeIntegration(db.pool, id)).outcome).toBe('already-integrated')
    expect(repos.get('equipe/deja')!.prs.size).toBe(0)
    const none = await createProject(db.pool, { name: 'equipe/x', sourceKind: 'git', forgeId: forges.forgejo, repoFullName: 'equipe/x', repoUrl: 'https://forgejo.exemple.test/equipe/x.git', defaultBranch: 'main' })
    expect((await proposeIntegration(db.pool, none.id)).outcome).toBe('pending-detection')
    const archive = await createProject(db.pool, { name: 'archive', sourceKind: 'archive' })
    expect((await proposeIntegration(db.pool, archive.id)).outcome).toBe('not-applicable')
  })

  it('mode tiré : workflow sur les tags seulement, qui attend scanoria/release-gate', async () => {
    const r = repo('equipe/tire')
    const id = await project('forgejo', 'equipe/tire', [], { mode: 'pull' })
    await db.pool.query(`UPDATE projects SET release_patterns = '{v*,release-*}' WHERE id = $1`, [id])
    expect((await proposeIntegration(db.pool, id)).outcome).toBe('opened')
    const wf = r.pushed['.forgejo/workflows/scanoria.yml']!
    expect(wf).toContain('SCANORIA_MODE: pull')
    expect(wf).not.toContain('pull_request:')
    expect(wf).toContain('tags: ["v*", "release-*"]')
    expect(r.prs.get(1)!.body).toContain('scanoria/release-gate')
  })

  it('GitHub : workflow GitHub (id-token: write) ; droit manquant de l’application signalé', async () => {
    const r = repo('equipe/gh')
    const id = await project('github', 'equipe/gh', [{ kind: 'github-actions', path: '.github/workflows/ci.yml' }])
    expect((await proposeIntegration(db.pool, id, { locale: 'en' })).outcome).toBe('opened')
    expect(r.pushed['.github/workflows/scanoria.yml']).toContain('id-token: write')
    expect(r.prs.get(1)!.title).toBe('Scanoria: add the analysis step to the CI')

    repo('equipe/ghrefus')
    deny = new Set(['POST /repos/equipe/ghrefus/git/refs'])
    const id2 = await project('github', 'equipe/ghrefus', [])
    const out = await proposeIntegration(db.pool, id2)
    expect(out).toMatchObject({ outcome: 'error', code: 'E_FORGE_AUTH' })
    const req = (await listIntegrationRequests(db.pool, id2))[0]!
    expect(req).toMatchObject({ kind: 'ci-pr', state: 'error' })
    expect(req.detail.missing_permission).toContain('contents: write')
    deny = new Set()
  })

  it('GitLab : composant, étape commune et include ajouté à .gitlab-ci.yml ; include existant → ligne manuelle', async () => {
    const r = repo('groupe/app', { '.gitlab-ci.yml': 'stages: [test]\n' })
    const id = await project('gitlab', 'groupe/app', [{ kind: 'gitlab-ci', path: '.gitlab-ci.yml' }])
    expect((await proposeIntegration(db.pool, id)).outcome).toBe('opened')
    expect(r.pushed['create:.gitlab/scanoria.yml']).toContain('id_tokens:')
    expect(r.pushed['update:.gitlab-ci.yml']).toMatch(/^stages: \[test\]\n\n# Scanoria[^\n]*\ninclude:\n {2}- local: \.gitlab\/scanoria\.yml/)
    expect(r.pushed['update:.gitlab-ci.yml']).toContain(`project: ${id}`)

    const r2 = repo('groupe/inc', { '.gitlab-ci.yml': 'include:\n  - local: autre.yml\n' })
    const id2 = await project('gitlab', 'groupe/inc', [{ kind: 'gitlab-ci', path: '.gitlab-ci.yml' }])
    expect((await proposeIntegration(db.pool, id2)).outcome).toBe('opened')
    expect(Object.keys(r2.pushed).sort()).toEqual(['create:.gitlab/scanoria-ci.sh', 'create:.gitlab/scanoria.yml'])
    expect(r2.prs.get(1)!.body).toContain('local: .gitlab/scanoria.yml')
  })

  it('Jenkins : bibliothèque et ligne d’appel dans la PR', async () => {
    const r = repo('equipe/jenkins', { Jenkinsfile: 'pipeline {}' })
    const id = await project('forgejo', 'equipe/jenkins', [{ kind: 'jenkins', path: 'Jenkinsfile' }])
    expect((await proposeIntegration(db.pool, id)).outcome).toBe('opened')
    expect(Object.keys(r.pushed).sort()).toEqual(['ci/scanoria/resources/scanoria-ci.sh', 'ci/scanoria/vars/scanoria.groovy'])
    expect(r.prs.get(1)!.body).toContain(`scanoria(url: '${CONSOLE}', project: '${id}'`)
  })

  it('sans adresse de console, mode poussé : erreur rangée, rien d’écrit', async () => {
    setConsoleUrl(null)
    repo('equipe/sansurl')
    const id = await project('forgejo', 'equipe/sansurl', [], { mode: 'push' })
    const before = writes().length
    expect(await proposeIntegration(db.pool, id)).toMatchObject({ outcome: 'error', code: 'E_CONSOLE_URL' })
    expect(writes().length).toBe(before)
    setConsoleUrl(CONSOLE)
  })

  describe('protection de branche', () => {
    it('jamais appliquée sans décision : la base refuse « applied » sans decided_by', async () => {
      const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/app'`)).rows[0]!.id
      const req = (await listIntegrationRequests(db.pool, id)).find(x => x.kind === 'branch-protection')!
      await expect(db.pool.query(`UPDATE integration_requests SET state = 'applied' WHERE id = $1`, [req.id])).rejects.toThrow(/integration_protection_decided/)
      expect(repos.get('equipe/app')!.protection).toBeNull()
    })

    it('Forgejo : appliquée par un administrateur, contexte PR ; ajoutée à une règle existante sans rien retirer', async () => {
      const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/app'`)).rows[0]!.id
      const req = (await listIntegrationRequests(db.pool, id)).find(x => x.kind === 'branch-protection')!
      expect(req.detail).toMatchObject({ branch: 'main', contexts: ['scanoria/rapide'] })
      const out = await decideProtection(db.pool, id, req.id, { action: 'apply', ...admin })
      expect(out).toMatchObject({ state: 'applied', decided_by: String(admin.userId), decided_by_username: 'admin' })
      expect(repos.get('equipe/app')!.protection).toEqual(['scanoria/rapide'])
      await expect(decideProtection(db.pool, id, req.id, { action: 'apply', ...admin })).rejects.toMatchObject({ code: 'E_INTEGRATION_STATE' })

      // Règle existante : contextes ajoutés, avec le gate de release coché.
      const r = repos.get('equipe/tire')!
      r.protection = ['ci/tests']
      const id2 = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/tire'`)).rows[0]!.id
      const req2 = (await listIntegrationRequests(db.pool, id2)).find(x => x.kind === 'branch-protection')!
      await decideProtection(db.pool, id2, req2.id, { action: 'apply', includeReleaseGate: true, ...admin })
      expect(r.protection).toEqual(['ci/tests', 'scanoria/rapide', 'scanoria/release-gate'])
      const a = (await db.pool.query<{ details: Record<string, unknown> }>(`SELECT details FROM audit_log WHERE action = 'integration.protection-apply' AND target_id = $1`, [id2])).rows
      expect(a[0]!.details.contexts).toEqual(['scanoria/rapide', 'scanoria/release-gate'])
    })

    it('GitHub : droit manquant signalé, proposition gardée ; refus tracé', async () => {
      const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/gh'`)).rows[0]!.id
      const req = (await listIntegrationRequests(db.pool, id)).find(x => x.kind === 'branch-protection')!
      deny = new Set(['PUT /repos/equipe/gh/branches/main/protection'])
      const out = await decideProtection(db.pool, id, req.id, { action: 'apply', ...admin })
      expect(out.state).toBe('proposed')
      expect(out.detail).toMatchObject({ error: 'E_FORGE_AUTH', missing_permission: 'administration: write' })
      deny = new Set()
      const ok = await decideProtection(db.pool, id, req.id, { action: 'apply', ...admin })
      expect(ok.state).toBe('applied')
      expect(ok.detail.error).toBeUndefined()
      expect(repos.get('equipe/gh')!.protection).toEqual(['scanoria/rapide'])

      const id2 = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/jenkins'`)).rows[0]!.id
      const req2 = (await listIntegrationRequests(db.pool, id2)).find(x => x.kind === 'branch-protection')!
      expect((await decideProtection(db.pool, id2, req2.id, { action: 'decline', ...admin })).state).toBe('declined')
      expect(repos.get('equipe/jenkins')!.protection).toBeNull()
      // Proposée de nouveau à la demande, jamais appliquée seule.
      const again = await requestProtection(db.pool, id2)
      expect(again).not.toBe(req2.id)
      expect(await requestProtection(db.pool, id2)).toBe(again)
    })

    it('GitLab : « pipelines must succeed »', async () => {
      const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'groupe/app'`)).rows[0]!.id
      const req = (await listIntegrationRequests(db.pool, id)).find(x => x.kind === 'branch-protection')!
      expect((await decideProtection(db.pool, id, req.id, { action: 'apply', ...admin })).state).toBe('applied')
      expect(repos.get('groupe/app')!.protection).toEqual(['pipeline'])
    })
  })

  it('J16 : case « chaîne autonome » enregistrée avec l’audit, une fois par changement', async () => {
    const id = (await db.pool.query<{ id: string }>(`SELECT id::text FROM projects WHERE repo_full_name = 'equipe/app'`)).rows[0]!.id
    expect(await setAutonomousChain(db.pool, id, true, admin)).toBe(true)
    expect(await setAutonomousChain(db.pool, id, true, admin)).toBe(false)
    expect((await db.pool.query(`SELECT autonomous_chain FROM projects WHERE id = $1`, [id])).rows[0]).toEqual({ autonomous_chain: true })
    const a = (await db.pool.query(`SELECT details FROM audit_log WHERE action = 'project.autonomous-chain' AND target_id = $1`, [id])).rows
    expect(a).toEqual([{ details: { enabled: true } }])
  })
})
