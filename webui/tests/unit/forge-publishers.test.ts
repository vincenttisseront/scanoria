// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 pour GitHub et GitLab (chantier D, 0.7) : chaque méthode du
// client de publication contre un transport simulé qui enregistre les appels
// (adresse, méthode, corps) et répond selon la route.

import { afterAll, beforeEach, describe, expect, it } from 'vitest'
import { setForgeRetryDelays, setForgeTransport } from '../../server/forges/http'
import { githubPublisher } from '../../server/forges/publish-github'
import { gitlabPublisher } from '../../server/forges/publish-gitlab'
import { gitlabClient, gitlabToRepo } from '../../server/forges/gitlab'
import { toPermission, type Annotation, type PullRequestRef } from '../../server/forges/pr-types'

const A = 'a'.repeat(40)
const B = 'b'.repeat(40)
const TOKEN = `jeton-${'x'.repeat(30)}`

interface Call { method: string, url: string, body: Record<string, unknown> | null }
let calls: Call[] = []
type Route = (c: Call) => { status: number, body?: unknown } | null
let routes: Route[] = []

function json(status: number, body: unknown): Response {
  if (typeof body === 'string') return new Response(body, { status, headers: { 'content-type': 'text/plain' } })
  return new Response(status === 204 ? null : JSON.stringify(body ?? {}), { status, headers: { 'content-type': 'application/json' } })
}

function parseBody(b: unknown): Record<string, unknown> | null {
  if (b === undefined || b === null) return null
  const text = typeof b === 'string' ? b : Buffer.from(b as Uint8Array).toString('utf8')
  return text ? JSON.parse(text) as Record<string, unknown> : null
}

beforeEach(() => {
  calls = []
  routes = []
  setForgeRetryDelays([0, 0])
  setForgeTransport(async (url, init) => {
    const c: Call = { method: init.method ?? 'GET', url, body: parseBody(init.body) }
    calls.push(c)
    for (const r of routes) {
      const out = r(c)
      if (out) return json(out.status, out.body)
    }
    return json(404, {})
  })
})

afterAll(() => {
  setForgeTransport()
  setForgeRetryDelays()
})

const on = (method: string, re: RegExp, status: number, body?: unknown | ((c: Call) => unknown)) =>
  routes.push(c => (c.method === method && re.test(c.url) ? { status, body: typeof body === 'function' ? (body as (c: Call) => unknown)(c) : body } : null))

const pr: PullRequestRef = { number: 5, head_sha: A, head_ref: 'feat/x', base_sha: B, base_ref: 'main', author: 'dev-une', draft: false }
const ann = (n: number): Annotation[] => Array.from({ length: n }, (_, i) => ({ path: 'src/a.ts', line: i + 1, level: i % 3 === 0 ? 'failure' : i % 3 === 1 ? 'warning' : 'notice', title: `R${i}`, message: 'm' }))

describe('client de publication GitHub', () => {
  const gh = githubPublisher({ kind: 'github', base_url: 'https://api.github.com', token: TOKEN })

  it('statut, commentaire créé puis mis à jour, identifiant refusé', async () => {
    on('POST', /\/repos\/equipe\/app\/statuses\/a{40}$/, 201, {})
    on('POST', /\/issues\/5\/comments$/, 201, { id: 77 })
    on('PATCH', /\/issues\/comments\/77$/, 200, {})
    await gh.setCommitStatus('equipe/app', { sha: A, state: 'failure', context: 'scanoria/pr', description: 'd', target_url: 'https://analyse.exemple.test/scans/1' })
    expect(calls[0]!.body).toMatchObject({ state: 'failure', context: 'scanoria/pr', target_url: 'https://analyse.exemple.test/scans/1' })
    expect(calls[0]!.url.startsWith('https://api.github.com/repos/')).toBe(true)
    expect(await gh.createComment('equipe/app', 5, 'corps')).toBe('77')
    await gh.updateComment('equipe/app', 5, '77', 'corps 2')
    expect(calls.at(-1)).toMatchObject({ method: 'PATCH', body: { body: 'corps 2' } })
    await expect(gh.updateComment('equipe/app', 5, '../x', 'c')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
    on('POST', /\/issues\/6\/comments$/, 201, {})
    await expect(gh.createComment('equipe/app', 6, 'c')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
  })

  it('check run par lots de 50, conclusion traduite', async () => {
    on('POST', /\/check-runs$/, 201, { id: 9 })
    on('PATCH', /\/check-runs\/9$/, 200, {})
    const res = await gh.publishAnnotations('equipe/app', pr, ann(120), 'résumé', 'pending')
    expect(res).toEqual({ kind: 'check-run', id: '9', count: 120 })
    const first = calls[0]!.body as { conclusion: string, output: { annotations: { annotation_level: string }[] } }
    expect(first.conclusion).toBe('neutral')
    expect(first.output.annotations).toHaveLength(50)
    expect(first.output.annotations.map(x => x.annotation_level).slice(0, 3)).toEqual(['failure', 'warning', 'notice'])
    expect(calls.filter(c => c.method === 'PATCH')).toHaveLength(2)
  })

  it('jeton sans droit check run : revue de PR ; autre erreur propagée', async () => {
    on('POST', /\/check-runs$/, 403, { message: 'Resource not accessible by personal access token' })
    on('POST', /\/pulls\/5\/reviews$/, 200, { id: 31 })
    expect(await gh.publishAnnotations('equipe/app', pr, ann(2), 'résumé', 'failure')).toEqual({ kind: 'pr-review', id: '31', count: 2 })
    const review = calls.find(c => c.url.endsWith('/reviews'))!.body as { commit_id: string, event: string, comments: unknown[] }
    expect(review).toMatchObject({ commit_id: A, event: 'COMMENT' })
    expect(review.comments).toHaveLength(2)
    // Sans annotation, pas de revue de repli : l'erreur remonte.
    await expect(gh.publishAnnotations('equipe/app', pr, [], 'résumé', 'failure')).rejects.toMatchObject({ code: 'E_FORGE_AUTH' })
  })

  it('fichiers modifiés (supprimés exclus, bornés), auteurs, PR, PR ouvertes, commentaires', async () => {
    on('GET', /\/pulls\/5\/files\?/, 200, [{ filename: 'a.ts', status: 'modified' }, { filename: 'b.ts', status: 'removed' }, { filename: 'c.ts', status: 'added' }])
    expect(await gh.changedFiles('equipe/app', 5, 10)).toEqual({ files: ['a.ts', 'c.ts'], truncated: false })
    expect(await gh.changedFiles('equipe/app', 5, 1)).toEqual({ files: ['a.ts'], truncated: true })
    on('GET', /\/commits\/a{40}$/, 200, { author: { login: 'dev-une' }, committer: { login: 'web-flow' }, commit: { author: { email: 'dev-une@exemple.test' }, committer: { email: 'dev-une@exemple.test' } } })
    expect(await gh.commitAuthors('equipe/app', A)).toEqual(expect.arrayContaining(['dev-une', 'dev-une@exemple.test']))
    const raw = { number: 5, head: { sha: A, ref: 'feat/x' }, base: { sha: B, ref: 'main' }, user: { login: 'dev-une' }, draft: false }
    on('GET', /\/pulls\/5$/, 200, raw)
    expect(await gh.pullRequest('equipe/app', 5)).toMatchObject({ number: 5, head_sha: A, base_sha: B })
    on('GET', /\/pulls\/6$/, 200, { number: 6 })
    await expect(gh.pullRequest('equipe/app', 6)).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    on('GET', /\/pulls\?state=open/, 200, [raw, { number: 'x' }])
    expect(await gh.openPullRequests('equipe/app', 20)).toHaveLength(1)
    on('GET', /\/issues\/5\/comments\?/, 200, [
      { id: 1, body: '/scanoria accept', created_at: '2026-11-25T10:00:00Z', user: { login: 'relectrice', type: 'User' } },
      { id: 2, body: 'robot', user: { login: 'scanoria[bot]', type: 'Bot' } },
      { id: 'x', body: 'invalide' },
    ])
    const cs = await gh.comments('equipe/app', 5, '2026-11-24T00:00:00Z')
    expect(cs.map(c => [c.id, c.author_is_bot])).toEqual([['1', false], ['2', true]])
    expect(calls.at(-1)!.url).toContain('since=2026-11-24T00%3A00%3A00Z')
    expect(await gh.ensureWebhook('equipe/app', 'https://analyse.exemple.test/api/forges/x/webhook', 's'.repeat(32))).toBe('app')
  })
})

describe('client de publication GitLab', () => {
  const gl = gitlabPublisher({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: TOKEN })
  const mr = { iid: 5, sha: A, source_branch: 'feat/x', target_branch: 'main', diff_refs: { base_sha: B }, author: { username: 'dev-une' }, draft: true }

  it('statut (échec → failed), note créée et mise à jour', async () => {
    on('POST', /\/projects\/equipe%2Fapp\/statuses\/a{40}$/, 201, {})
    on('POST', /\/merge_requests\/5\/notes$/, 201, { id: 12 })
    on('PUT', /\/merge_requests\/5\/notes\/12$/, 200, {})
    await gl.setCommitStatus('equipe/app', { sha: A, state: 'error', context: 'scanoria/pr', description: 'd', target_url: null })
    expect(calls[0]!.body).toMatchObject({ state: 'failed', name: 'scanoria/pr' })
    await gl.setCommitStatus('equipe/app', { sha: A, state: 'success', context: 'scanoria/pr', description: 'd', target_url: null })
    expect(calls[1]!.body).toMatchObject({ state: 'success' })
    expect(await gl.createComment('equipe/app', 5, 'c')).toBe('12')
    await gl.updateComment('equipe/app', 5, '12', 'c2')
    expect(calls.at(-1)).toMatchObject({ method: 'PUT', body: { body: 'c2' } })
    await expect(gl.updateComment('equipe/app', 5, 'x/y', 'c')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
    on('POST', /\/merge_requests\/6\/notes$/, 201, {})
    await expect(gl.createComment('equipe/app', 6, 'c')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
  })

  it('annotations en discussions ; ligne hors du diff (400) ignorée, autre erreur propagée', async () => {
    let n = 0
    routes.push(c => (c.method === 'POST' && c.url.endsWith('/discussions')
      ? (++n === 2 ? { status: 400, body: { message: 'line_code' } } : { status: 201, body: { id: `d${n}` } })
      : null))
    const res = await gl.publishAnnotations('equipe/app', pr, ann(3), 'résumé', 'failure')
    expect(res).toEqual({ kind: 'pr-review', id: 'd1', count: 2 })
    expect(calls[0]!.body).toMatchObject({ position: { base_sha: B, head_sha: A, new_path: 'src/a.ts', new_line: 1 } })
    routes = []
    on('POST', /\/discussions$/, 403, {})
    await expect(gl.publishAnnotations('equipe/app', pr, ann(1), 'r', 'failure')).rejects.toMatchObject({ code: 'E_FORGE_AUTH' })
  })

  it('fichiers, auteurs, MR, MR ouvertes relues une à une, notes système exclues, webhook', async () => {
    on('GET', /\/merge_requests\/5\/diffs\?/, 200, [{ new_path: 'a.ts' }, { new_path: 'b.ts', deleted_file: true }])
    expect(await gl.changedFiles('equipe/app', 5, 10)).toEqual({ files: ['a.ts'], truncated: false })
    on('GET', /\/repository\/commits\/a{40}$/, 200, { author_email: 'dev-une@exemple.test', committer_email: 'dev-une@exemple.test' })
    expect(await gl.commitAuthors('equipe/app', A)).toEqual(['dev-une@exemple.test'])
    on('GET', /\/merge_requests\/5$/, 200, mr)
    expect(await gl.pullRequest('equipe/app', 5)).toMatchObject({ number: 5, head_sha: A, base_sha: B, draft: true, author: 'dev-une' })
    on('GET', /\/merge_requests\/6$/, 200, { iid: 6 })
    await expect(gl.pullRequest('equipe/app', 6)).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    on('GET', /\/merge_requests\?state=opened/, 200, [{ iid: 5 }, { iid: 6 }, { iid: 'x' }])
    expect((await gl.openPullRequests('equipe/app', 20)).map(p => p.number)).toEqual([5])
    on('GET', /\/merge_requests\/5\/notes\?/, 200, [
      { id: 1, body: 'ancienne', created_at: '2026-11-20T00:00:00Z', author: { username: 'a' } },
      { id: 2, body: '/scanoria accept', created_at: '2026-11-25T00:00:00Z', author: { username: 'relectrice' } },
      { id: 3, body: 'a changé la description', created_at: '2026-11-25T00:00:00Z', system: true, author: { username: 'a' } },
      { id: 4, body: 'robot', created_at: '2026-11-25T00:00:00Z', author: { username: 'bot', bot: true } },
    ])
    expect((await gl.comments('equipe/app', 5, '2026-11-24T00:00:00Z')).map(c => [c.id, c.author_is_bot])).toEqual([['2', false], ['4', true]])
    const url = 'https://analyse.exemple.test/api/forges/x/webhook'
    on('GET', /\/hooks\?/, 200, [{ url }])
    expect(await gl.ensureWebhook('equipe/app', url, 's'.repeat(32))).toBe('exists')
    routes = []
    on('GET', /\/hooks\?/, 200, [])
    on('POST', /\/hooks$/, 201, { id: 1 })
    expect(await gl.ensureWebhook('equipe/app', url, 's'.repeat(32))).toBe('created')
    expect(calls.at(-1)!.body).toMatchObject({ url, token: 's'.repeat(32), merge_requests_events: true, note_events: true, enable_ssl_verification: true })
  })
})

describe('client de découverte GitLab', () => {
  const proj = (path: string, patch: Record<string, unknown> = {}) => ({
    path_with_namespace: path, path: path.split('/').pop(), http_url_to_repo: `https://gitlab.exemple.test/${path}.git`, ssh_url_to_repo: null,
    web_url: `https://gitlab.exemple.test/${path}`, default_branch: 'main', visibility: 'private', description: 'd', ...patch,
  })

  it('dépôt normalisé ; entrées invalides écartées', () => {
    expect(gitlabToRepo(proj('equipe/app', { archived: true, forked_from_project: { id: 1 }, empty_repo: true }))).toMatchObject({
      full_name: 'equipe/app', name: 'app', private: true, archived: true, fork: true, empty: true, default_branch: 'main',
    })
    expect(gitlabToRepo(proj('equipe/app', { http_url_to_repo: 'git://x' }))).toBeNull()
    expect(gitlabToRepo(proj('equipe/app', { default_branch: '../x' }))!.default_branch).toBeNull()
    expect(gitlabToRepo(null)).toBeNull()
  })

  it('jeton : utilisateur, projets membres, dépôt, branches, dernier commit, arbre, fichier', async () => {
    const gl = gitlabClient({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: TOKEN })
    on('GET', /\/api\/v4\/user$/, 200, { username: 'scanoria-bot' })
    expect(await gl.check()).toEqual({ login: 'scanoria-bot' })
    on('GET', /\/projects\?membership=true/, 200, [proj('equipe/app'), { path_with_namespace: 1 }])
    expect((await gl.listRepos()).map(r => r.full_name)).toEqual(['equipe/app'])
    on('GET', /\/projects\/equipe%2Fapp$/, 200, proj('equipe/app'))
    expect((await gl.repo('equipe/app')).clone_url).toBe('https://gitlab.exemple.test/equipe/app.git')
    on('GET', /\/projects\/equipe%2Fvide$/, 200, {})
    await expect(gl.repo('equipe/vide')).rejects.toMatchObject({ code: 'E_FORGE_RESPONSE' })
    on('GET', /\/repository\/branches\?/, 200, [{ name: 'main' }, { name: 'dev' }, {}])
    expect(await gl.branches('equipe/app')).toEqual(['main', 'dev'])
    on('GET', /\/repository\/branches\/main$/, 200, { commit: { id: A } })
    expect(await gl.latestCommit('equipe/app', 'main')).toBe(A)
    on('GET', /\/repository\/tree\?/, 200, [{ path: 'src', type: 'tree' }, { path: 'src/a.ts', type: 'blob' }, { type: 'blob' }])
    expect(await gl.listTree('equipe/app', 'main')).toEqual({ entries: [{ path: 'src', type: 'dir', size: null }, { path: 'src/a.ts', type: 'file', size: null }], truncated: false })
    expect((await gl.listTree('equipe/app', 'main', { maxEntries: 1 })).truncated).toBe(true)
    on('GET', /\/files\/package\.json\/raw\?/, 200, '{"name":"app"}')
    expect(await gl.readFile('equipe/app', 'main', 'package.json')).toBe('{"name":"app"}')
    expect(await gl.readFile('equipe/app', 'main', 'absent.txt')).toBeNull()
    on('GET', /\/files\/gros\.bin\/raw\?/, 200, 'x'.repeat(64))
    expect(await gl.readFile('equipe/app', 'main', 'gros.bin', { maxBytes: 8 })).toBeNull()
  })

  it('sans jeton : version, sinon projets publics ; dépôts publics seulement', async () => {
    const anon = gitlabClient({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: null })
    on('GET', /\/api\/v4\/version$/, 401, {})
    on('GET', /\/projects\?per_page=1$/, 200, [])
    expect(await anon.check()).toEqual({ login: null })
    expect(calls.map(c => new URL(c.url).pathname + new URL(c.url).search)).toEqual(['/api/v4/version', '/api/v4/projects?per_page=1'])
    on('GET', /\/projects\?visibility=public/, 200, [proj('public/outil', { visibility: 'public' })])
    expect((await anon.listRepos())[0]).toMatchObject({ full_name: 'public/outil', private: false })
  })
})

describe('droit d’un compte sur le dépôt (/scanoria accept)', () => {
  it('GitHub : droit lu, compte absent ou refusé → aucun droit, identifiant contrôlé', async () => {
    const gh = githubPublisher({ kind: 'github', base_url: 'https://api.github.com', token: TOKEN })
    on('GET', /\/collaborators\/relectrice\/permission$/, 200, { permission: 'write', role_name: 'maintain' })
    on('GET', /\/collaborators\/admin-une\/permission$/, 200, { permission: 'admin' })
    on('GET', /\/collaborators\/inconnu\/permission$/, 404, {})
    on('GET', /\/collaborators\/cache\/permission$/, 403, {})
    expect(await gh.permission('equipe/app', 'relectrice')).toBe('write')
    expect(await gh.permission('equipe/app', 'admin-une')).toBe('admin')
    expect(await gh.permission('equipe/app', 'inconnu')).toBe('none')
    expect(await gh.permission('equipe/app', 'cache')).toBe('none')
    await expect(gh.permission('equipe/app', '../x')).rejects.toMatchObject({ code: 'E_FORGE_INPUT' })
  })

  it('GitLab : niveau d’accès du membre (Developer et plus = écriture)', async () => {
    const gl = gitlabPublisher({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: TOKEN })
    on('GET', /\/members\/all\?query=dev/, 200, [{ username: 'dev-une', access_level: 30 }, { username: 'dev', access_level: 20 }])
    on('GET', /\/members\/all\?query=chef/, 200, [{ username: 'chef', access_level: 40 }])
    on('GET', /\/members\/all\?query=absent/, 200, [])
    expect(await gl.permission('equipe/app', 'dev')).toBe('read')
    expect(await gl.permission('equipe/app', 'chef')).toBe('admin')
    expect(await gl.permission('equipe/app', 'absent')).toBe('none')
  })

  it('toPermission : niveaux ramenés à trois', () => {
    expect(['admin', 'owner', 'maintain', 'push', 'write', 'triage', 'pull', 'read', 'x', null].map(toPermission))
      .toEqual(['admin', 'admin', 'write', 'write', 'write', 'read', 'read', 'read', 'none', 'none'])
  })
})
