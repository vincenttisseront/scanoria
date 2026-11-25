// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier A contre PostgreSQL et de faux serveurs Forgejo et GitHub :
// clients de forge (pagination, 401, 404, 429, réponse énorme, redirections),
// secrets en base, découverte, détection et planification (enqueueScan simulé
// tant que le chantier C n'est pas fusionné).

import { mkdtemp, rm, unlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { DATABASE_URL, createTestDatabase, type TestDatabase } from '../helpers/db'
import { fakeSha, newFakeForge, startFakeForges, type FakeForge, type FakeForgeServer } from '../helpers/fake-forge'
import { loadConfig, setConfig } from '../../server/utils/config'
import { SecretError, decryptSecret, encryptSecret, rotateSecret, secretInfo } from '../../server/utils/secrets'
import { ForgeError, forgeClient, getForge } from '../../server/forges'
import { createForge } from '../../server/projects/forges'
import { discoverForge } from '../../server/projects/discover'
import { runProjectSchedules, type EnqueueScan } from '../../server/projects/schedule'
import { createProject, getProject, listProjects, refreshDetection } from '../../server/projects/service'

const FORGEJO = 'forge.exemple.test'

function repoFiles() {
  return {
    'package.json': '{"license":"MIT"}', 'package-lock.json': '{}', 'src/index.ts': '', 'Dockerfile': 'FROM scratch',
    '.forgejo/workflows/ci.yml': 'on: push',
  }
}

describe.skipIf(!DATABASE_URL)('forges et projets (PostgreSQL, faux serveurs)', () => {
  let db: TestDatabase
  let dir: string
  let fake: FakeForgeServer
  let forgejo: FakeForge
  let github: FakeForge
  const actor = { type: 'system' as const }

  beforeAll(async () => {
    db = await createTestDatabase()
    dir = await mkdtemp(join(tmpdir(), 'scanoria-forges-'))
    process.env.NUXT_SECRET_KEY_FILE = join(dir, 'secret.key')
    setConfig(loadConfig({
      NUXT_DATABASE_URL: db.url,
      NUXT_UPLOADS_DIR: join(dir, 'uploads'),
      NUXT_CATALOG_INDEX_FILE: join(dir, 'absent-index.json'),
      NUXT_MODULES_STATE_FILE: join(dir, 'absent-state.json'),
    }))
    const many = Array.from({ length: 120 }, (_, i) => ({ full_name: `equipe/depot-${String(i).padStart(3, '0')}`, default_branch: 'main' }))
    forgejo = newFakeForge('forgejo', FORGEJO, [
      { full_name: 'equipe/app', default_branch: 'main', private: true, files: repoFiles(), branches: { 'main': fakeSha(), 'release/1.0': fakeSha() } },
      { full_name: 'equipe/vieux', default_branch: 'main', archived: true },
      { full_name: 'equipe/vide', default_branch: 'main', empty: true },
      ...many,
    ])
    github = newFakeForge('github', 'github.com', [
      { full_name: 'libre/outil', default_branch: 'trunk', files: { 'go.mod': '', 'go.sum': '', 'main.go': '' } },
    ])
    fake = await startFakeForges([forgejo, github])
  })

  afterAll(async () => {
    await fake?.close()
    delete process.env.NUXT_SECRET_KEY_FILE
    await db?.drop()
    if (dir) await rm(dir, { recursive: true, force: true })
  })

  beforeEach(() => {
    forgejo.faults.clear()
    github.faults.clear()
  })

  describe('clients', () => {
    it('Forgejo : vérification, pagination des dépôts, dépôt, branches, commit, arbre et fichiers', async () => {
      const c = forgeClient({ kind: 'forgejo', base_url: `https://${FORGEJO}`, token: forgejo.token })
      expect(await c.check()).toEqual({ login: 'robot' })
      const repos = await c.listRepos()
      expect(repos).toHaveLength(123)
      expect(forgejo.requests.filter(r => r.path.startsWith('/api/v1/user/repos')).length).toBe(3)
      expect(forgejo.requests.every(r => r.auth === `token ${forgejo.token}`)).toBe(true)
      const app = await c.repo('equipe/app')
      expect(app).toMatchObject({ full_name: 'equipe/app', private: true, default_branch: 'main', clone_url: `https://${FORGEJO}/equipe/app.git` })
      expect((await c.branches('equipe/app')).sort()).toEqual(['main', 'release/1.0'])
      expect(await c.latestCommit('equipe/app', 'release/1.0')).toMatch(/^[0-9a-f]{40}$/)
      const tree = await c.listTree('equipe/app', 'main')
      expect(tree.truncated).toBe(false)
      expect(tree.entries.filter(e => e.type === 'file').map(e => e.path).sort()).toEqual(Object.keys(repoFiles()).sort())
      const small = await c.listTree('equipe/app', 'main', { maxEntries: 2 })
      expect(small).toMatchObject({ truncated: true })
      expect(small.entries).toHaveLength(2)
      expect(await c.readFile('equipe/app', 'main', 'package.json')).toBe('{"license":"MIT"}')
      expect(await c.readFile('equipe/app', 'main', 'absent.txt')).toBeNull()
      expect(await c.readFile('equipe/app', 'main', 'package.json', { maxBytes: 4 })).toBeNull()
    })

    it('Forgejo sans jeton : dépôts publics seulement', async () => {
      const c = forgeClient({ kind: 'forgejo', base_url: `https://${FORGEJO}` })
      expect(await c.check()).toEqual({ login: null })
      const repos = await c.listRepos()
      expect(repos.some(r => r.full_name === 'equipe/app')).toBe(false)
      await expect(c.repo('equipe/app')).rejects.toMatchObject({ code: 'E_FORGE_NOT_FOUND' })
    })

    it('GitHub : anonyme sur un dépôt public, liste vide sans jeton ; avec jeton', async () => {
      const anon = forgeClient({ kind: 'github', base_url: 'https://github.com' })
      expect(await anon.listRepos()).toEqual([])
      expect((await anon.repo('libre/outil')).default_branch).toBe('trunk')
      expect(await anon.latestCommit('libre/outil', 'trunk')).toMatch(/^[0-9a-f]{40}$/)
      expect((await anon.listTree('libre/outil', 'trunk')).entries.map(e => e.path).sort()).toEqual(['go.mod', 'go.sum', 'main.go'])
      expect(await anon.readFile('libre/outil', 'trunk', 'go.mod')).toBe('')
      const authed = forgeClient({ kind: 'github', base_url: 'https://github.com', token: github.token })
      expect(await authed.check()).toEqual({ login: 'robot' })
      expect(await authed.listRepos()).toHaveLength(1)
      expect(github.requests.some(r => r.auth === `Bearer ${github.token}`)).toBe(true)
    })

    it('erreurs : 401, 404, 429, quota GitHub, 500, énorme, redirection étrangère, injoignable ; jamais le jeton', async () => {
      const bad = forgeClient({ kind: 'forgejo', base_url: `https://${FORGEJO}`, token: 'scn_faux' })
      const errors: ForgeError[] = []
      const capture = async (p: Promise<unknown>) => {
        try {
          await p
        }
        catch (err) {
          errors.push(err as ForgeError)
          return (err as ForgeError).code
        }
        return 'ok'
      }
      expect(await capture(bad.check())).toBe('E_FORGE_AUTH')
      const c = forgeClient({ kind: 'forgejo', base_url: `https://${FORGEJO}`, token: forgejo.token })
      expect(await capture(c.repo('equipe/inconnu'))).toBe('E_FORGE_NOT_FOUND')
      forgejo.faults.set('/api/v1/user/repos', 'rate')
      expect(await capture(c.listRepos())).toBe('E_FORGE_RATE_LIMITED')
      github.faults.set('/user', 'rate')
      expect(await capture(forgeClient({ kind: 'github', base_url: 'https://github.com', token: github.token }).check())).toBe('E_FORGE_RATE_LIMITED')
      forgejo.faults.set('/api/v1/version', 'server')
      expect(await capture(forgeClient({ kind: 'forgejo', base_url: `https://${FORGEJO}` }).check())).toBe('E_FORGE_RESPONSE')
      forgejo.faults.set('/api/v1/repos/equipe/app/branches', 'huge')
      expect(await capture(c.branches('equipe/app'))).toBe('E_FORGE_TOO_LARGE')
      forgejo.faults.set('/api/v1/user', 'redirect-other')
      expect(await capture(c.check())).toBe('E_FORGE_REDIRECT')
      forgejo.faults.clear()
      forgejo.faults.set('/api/v1/user', 'redirect-same')
      expect(await capture(c.check())).toBe('ok')
      expect(await capture(forgeClient({ kind: 'forgejo', base_url: 'https://injoignable.exemple.test', token: forgejo.token }).check())).toBe('E_FORGE_UNREACHABLE')
      expect(await capture(c.latestCommit('equipe/app', '--upload-pack=id'))).toBe('E_FORGE_INPUT')
      expect(await capture(forgeClient({ kind: 'gitlab', base_url: 'https://injoignable.exemple.test' }).listRepos())).toBe('E_FORGE_UNREACHABLE')
      for (const e of errors) {
        expect(e).toBeInstanceOf(ForgeError)
        expect(`${e.message} ${e.stack}`).not.toContain(forgejo.token)
        expect(`${e.message} ${e.stack}`).not.toContain(github.token)
      }
    })
  })

  describe('secrets en base', () => {
    it('chiffrés, indice seul visible, rotation, clé recréée → échec propre', async () => {
      const id = await encryptSecret(db.pool, { kind: 'token', value: forgejo.token, username: 'robot' })
      const raw = await db.pool.query<{ secret_enc: Buffer, hint: string }>('SELECT secret_enc, hint FROM credentials WHERE id = $1', [id])
      expect(raw.rows[0]!.secret_enc.includes(Buffer.from(forgejo.token))).toBe(false)
      expect(raw.rows[0]!.hint).toBe(`…${forgejo.token.slice(-4)}`)
      expect(await decryptSecret(db.pool, id)).toEqual({ kind: 'token', value: forgejo.token, username: 'robot' })
      expect(await secretInfo(db.pool, id)).toMatchObject({ kind: 'token', username: 'robot', rotated_at: null })
      await rotateSecret(db.pool, id, 'nouvelle-valeur-de-test')
      expect((await decryptSecret(db.pool, id)).value).toBe('nouvelle-valeur-de-test')
      expect((await secretInfo(db.pool, id))!.rotated_at).toMatch(/Z$/)
      // Ligne déplacée : l'identifiant associé ne correspond plus.
      const other = await encryptSecret(db.pool, { kind: 'token', value: 'autre-valeur-de-test' })
      await db.pool.query('UPDATE credentials SET secret_enc = (SELECT secret_enc FROM credentials WHERE id = $1) WHERE id = $2', [id, other])
      await expect(decryptSecret(db.pool, other)).rejects.toThrow('E_SECRET_UNREADABLE')
      await expect(decryptSecret(db.pool, '00000000-0000-4000-8000-000000000000')).rejects.toThrow('E_SECRET_NOT_FOUND')
      await expect(encryptSecret(db.pool, { kind: 'token', value: '' })).rejects.toThrow(SecretError)
      await expect(rotateSecret(db.pool, '00000000-0000-4000-8000-000000000000', 'x')).rejects.toThrow('E_SECRET_NOT_FOUND')
      await unlink(process.env.NUXT_SECRET_KEY_FILE!)
      await expect(decryptSecret(db.pool, id)).rejects.toThrow('E_SECRET_UNREADABLE')
      // Les nouveaux secrets fonctionnent avec la nouvelle clé.
      const fresh = await encryptSecret(db.pool, { kind: 'token', value: forgejo.token })
      expect((await decryptSecret(db.pool, fresh)).value).toBe(forgejo.token)
    })
  })

  describe('découverte, détection et planification', () => {
    let forgeId: string

    it('ajout de forge vérifié, nom unique, puis découverte : un projet par dépôt utilisable', async () => {
      const { forge, login } = await createForge(db.pool, { kind: 'forgejo', name: 'Forge interne', base_url: `https://${FORGEJO}/`, token: forgejo.token, discovery: true }, actor)
      forgeId = forge.id
      expect(login).toBe('robot')
      expect(forge).toMatchObject({ base_url: `https://${FORGEJO}`, has_token: true, token_hint: `…${forgejo.token.slice(-4)}`, token_user: 'robot' })
      expect(JSON.stringify(forge)).not.toContain(forgejo.token)
      await expect(createForge(db.pool, { kind: 'forgejo', name: 'forge INTERNE', base_url: `https://${FORGEJO}`, discovery: true }, actor))
        .rejects.toMatchObject({ statusCode: 409 })
      await expect(createForge(db.pool, { kind: 'forgejo', name: 'Mauvais jeton', base_url: `https://${FORGEJO}`, token: 'scn_faux', discovery: true }, actor))
        .rejects.toMatchObject({ statusCode: 422, data: { code: 'E_FORGE_AUTH' } })
      await expect(createForge(db.pool, { kind: 'gitlab', name: 'GitLab', base_url: 'https://injoignable.exemple.test', discovery: true }, actor))
        .rejects.toMatchObject({ statusCode: 502, data: { code: 'E_FORGE_UNREACHABLE' } })
      await expect(createForge(db.pool, { kind: 'forgejo', name: 'Boucle', base_url: 'https://127.0.0.1', discovery: true }, actor))
        .rejects.toMatchObject({ statusCode: 400, data: { code: 'E_FORGE_URL' } })

      const result = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(result).toMatchObject({ repos: 123, skipped: 2, error: null })
      expect(result.created).toHaveLength(121)
      const projects = await listProjects(db.pool, { forgeId })
      expect(projects).toHaveLength(121)
      const app = projects.find(p => p.repo_full_name === 'equipe/app')!
      expect(app).toMatchObject({
        source_kind: 'git', schedule: 'on-commit', profile_slug: 'complet', gate_slug: 'defaut', default_branch: 'main',
        tracked_branches: ['main'], repo_url: `https://${FORGEJO}/equipe/app.git`, credential_kind: 'token', detection: null,
      })
      // Seconde découverte : rien de nouveau ; un projet archivé n'est pas recréé.
      await db.pool.query('UPDATE projects SET archived_at = now() WHERE id = $1', [app.id])
      const again = await discoverForge(db.pool, (await getForge(db.pool, forgeId))!)
      expect(again.created).toHaveLength(0)
      await db.pool.query('UPDATE projects SET archived_at = NULL WHERE id = $1', [app.id])
      const audit = await db.pool.query<{ details: Record<string, unknown> }>('SELECT details FROM audit_log WHERE action = \'forge.discover\' ORDER BY id')
      expect(audit.rows[0]!.details).toMatchObject({ repos: 123, created: 121 })
      const all = await db.pool.query<{ t: string }>('SELECT string_agg(details::text, \' \') AS t FROM audit_log')
      expect(all.rows[0]!.t).not.toContain(forgejo.token)
    })

    it('détection enregistrée (licence, modules) ; erreur de forge enregistrée sans lever', async () => {
      const app = (await listProjects(db.pool, { forgeId })).find(p => p.repo_full_name === 'equipe/app')!
      const updated = await refreshDetection(db.pool, app)
      expect(updated.detection).toMatchObject({ version: 1, languages: ['typescript'], containers: ['Dockerfile'], license: { spdx: 'MIT' } })
      expect(updated.spdx_license).toBe('MIT')
      forgejo.faults.set('/api/v1/repos/equipe/app/git/trees', 'server')
      const failed = await refreshDetection(db.pool, updated)
      expect(failed.detection).toMatchObject({ error: 'E_FORGE_RESPONSE' })
      forgejo.faults.clear()
    })

    it('on-commit : premier commit analysé, rien si inchangé, nouvelle analyse après un commit, 5 minutes entre deux interrogations', async () => {
      const calls: Parameters<EnqueueScan>[1][] = []
      let n = 0
      const enqueue: EnqueueScan = async (pool, input) => {
        calls.push(input)
        n++
        const { rows } = await pool.query<{ id: string }>(
          `INSERT INTO scans (project_id, number, trigger, priority, ref, commit_sha, profile_id, gate_id)
           SELECT id, $2, $3, 30, $4, $5, profile_id, gate_id FROM projects WHERE id = $1 RETURNING id::text`,
          [input.projectId, n, input.trigger, input.ref, input.commit ?? null])
        return { scanId: rows[0]!.id, number: n }
      }
      // Un seul projet suivi pour ce test : les autres passent en « none ».
      await db.pool.query(`UPDATE projects SET schedule = 'none', detection = '{"version":1}' WHERE repo_full_name <> 'equipe/app'`)
      const app = (await listProjects(db.pool, { forgeId })).find(p => p.repo_full_name === 'equipe/app')!
      await db.pool.query(`UPDATE projects SET tracked_branches = '{main,release/1.0}', last_polled_at = NULL WHERE id = $1`, [app.id])
      await db.pool.query(`UPDATE forges SET last_discovery_at = now()`)

      const t0 = new Date('2026-11-24T10:00:00Z')
      const r1 = await runProjectSchedules(db.pool, t0, enqueue)
      expect(r1).toMatchObject({ enqueued: 2, errors: 0 })
      expect(calls.map(c => [c.ref, c.trigger])).toEqual([['main', 'commit'], ['release/1.0', 'commit']])
      expect(calls[0]!.commit).toBe(forgejo.repos[0]!.branches!.main)
      expect((await getProject(db.pool, app.id))!.last_commit).toBe(forgejo.repos[0]!.branches!.main)

      // Moins de 5 minutes : pas d'interrogation.
      const before = forgejo.requests.length
      expect((await runProjectSchedules(db.pool, new Date(t0.getTime() + 60_000), enqueue)).enqueued).toBe(0)
      expect(forgejo.requests.length).toBe(before)
      // 5 minutes plus tard, rien de nouveau.
      expect((await runProjectSchedules(db.pool, new Date(t0.getTime() + 300_000), enqueue)).enqueued).toBe(0)
      // Nouveau commit sur main : une analyse, pour main seulement.
      forgejo.repos[0]!.branches!.main = fakeSha()
      const r4 = await runProjectSchedules(db.pool, new Date(t0.getTime() + 600_000), enqueue)
      expect(r4.enqueued).toBe(1)
      expect(calls.at(-1)).toMatchObject({ ref: 'main', commit: forgejo.repos[0]!.branches!.main, trigger: 'commit' })
      // Branche suivie supprimée sur la forge : erreur comptée, main reste analysée.
      const release = forgejo.repos[0]!.branches!['release/1.0']!
      delete forgejo.repos[0]!.branches!['release/1.0']
      forgejo.repos[0]!.branches!.main = fakeSha()
      const r45 = await runProjectSchedules(db.pool, new Date(t0.getTime() + 900_000), enqueue)
      expect(r45).toMatchObject({ enqueued: 1, errors: 1 })
      expect(calls.at(-1)).toMatchObject({ ref: 'main', commit: forgejo.repos[0]!.branches!.main })
      forgejo.repos[0]!.branches!['release/1.0'] = release
      // Forge en panne : erreur comptée, le cycle continue.
      forgejo.faults.set('/api/v1/repos/equipe/app/branches', 'server')
      const r5 = await runProjectSchedules(db.pool, new Date(t0.getTime() + 1_200_000), enqueue)
      expect(r5).toMatchObject({ enqueued: 0, errors: 1 })
    })

    it('daily et URL libre : une analyse par jour au créneau du projet', async () => {
      const calls: string[] = []
      let n = 100
      let clock = new Date()
      const enqueue: EnqueueScan = async (pool, input) => {
        calls.push(`${input.ref}:${input.trigger}`)
        n++
        // queued_at suit l'horloge simulée du test.
        const { rows } = await pool.query<{ id: string }>(
          `INSERT INTO scans (project_id, number, trigger, priority, ref, profile_id, gate_id, queued_at)
           SELECT id, $2, $3, 10, $4, profile_id, gate_id, $5 FROM projects WHERE id = $1 RETURNING id::text`,
          [input.projectId, n, input.trigger, input.ref, clock.toISOString()])
        return { scanId: rows[0]!.id, number: n }
      }
      await db.pool.query(`UPDATE projects SET schedule = 'none'`)
      const free = await createProject(db.pool, {
        name: 'libre', sourceKind: 'git', repoUrl: 'https://git.exemple.test/equipe/libre.git', defaultBranch: 'main', schedule: 'on-commit',
        detection: { version: 1, analyzed_at: '2026-11-24T00:00:00Z', error: 'E_NO_FORGE_ACCESS' },
      })
      const { currentDailySlot } = await import('../../server/projects/schedule')
      const slot = currentDailySlot(free.id, new Date('2026-11-25T12:00:00Z'))
      const day = new Date(Date.UTC(2026, 10, 25))
      const at = new Date(Math.max(slot.getTime(), day.getTime()) + 1000)
      const run = (d: Date) => {
        clock = d
        return runProjectSchedules(db.pool, d, enqueue)
      }
      expect((await run(at)).enqueued).toBe(1)
      expect(calls).toEqual(['main:schedule'])
      // Même créneau, 10 minutes plus tard : rien.
      expect((await run(new Date(at.getTime() + 600_000))).enqueued).toBe(0)
      // Créneau suivant (le lendemain) : une nouvelle analyse.
      expect((await run(new Date(at.getTime() + 86_400_000))).enqueued).toBe(1)
    })
  })
})
