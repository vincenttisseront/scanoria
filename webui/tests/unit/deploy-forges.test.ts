// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Écritures de déploiement des forges GitHub et GitLab (0.8, chantier D) :
// déclenchement sans réessai, suivi, lecture bornée, commit et PR, fusion
// automatique NATIVE liée au commit analysé. Faux serveurs en mémoire.

import { afterEach, describe, expect, it } from 'vitest'
import { setForgeTransport } from '../../server/forges/http'
import { forgeDeployer, gitlabStateOf, runStateOf } from '../../server/forges/deploy'
import { fakeToken } from '../helpers/fake-forge'

interface Call { method: string, url: string, body: unknown, auth: string | null }
type Route = [method: string, path: RegExp, reply: (call: Call) => [number, unknown]]

function fake(routes: Route[]) {
  const calls: Call[] = []
  setForgeTransport(async (url, init) => {
    const raw = typeof init.body === 'string' ? init.body : init.body instanceof Uint8Array ? Buffer.from(init.body).toString('utf8') : null
    const headers = new Headers(init.headers)
    const call = { method: (init.method ?? 'GET').toUpperCase(), url, body: raw ? JSON.parse(raw) as unknown : null, auth: headers.get('authorization') }
    calls.push(call)
    const path = new URL(url).pathname + new URL(url).search
    const r = routes.find(([m, p]) => m === call.method && p.test(path))
    const [status, data] = r ? r[2](call) : [404, {}]
    return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
  })
  return calls
}

afterEach(() => setForgeTransport())

const SHA = 'a'.repeat(40)
const HEAD = 'b'.repeat(40)
const b64 = (s: string) => Buffer.from(s).toString('base64')

describe('GitHub', () => {
  const gh = () => forgeDeployer({ kind: 'github', base_url: 'https://github.com', token: fakeToken() }, { consoleUrl: 'https://analyse.exemple.test' })

  it('déclenchement, run retrouvé, suivi', async () => {
    const since = new Date()
    const calls = fake([
      ['POST', /\/actions\/workflows\/deploy\.yml\/dispatches$/, () => [200, { workflow_run_id: 9, html_url: 'https://github.com/equipe/app/actions/runs/9' }]],
      ['GET', /\/actions\/workflows\/deploy\.yml\/runs\?/, () => [200, { workflow_runs: [{ id: 8, created_at: '2000-01-01T00:00:00Z' }, { id: 9, created_at: new Date(since.getTime() + 1000).toISOString(), html_url: 'https://github.com/equipe/app/actions/runs/9' }] }]],
      ['GET', /\/actions\/runs\/9$/, () => [200, { status: 'completed', conclusion: 'success', html_url: 'https://github.com/equipe/app/actions/runs/9' }]],
    ])
    const d = gh()
    expect(d.kind).toBe('github')
    expect(await d.dispatchWorkflow('equipe/app', 'deploy.yml', 'v1.0.0', { scanoria_commit: SHA })).toEqual({ runId: '9', url: 'https://github.com/equipe/app/actions/runs/9' })
    expect(calls[0]!.body).toMatchObject({ ref: 'v1.0.0', inputs: { scanoria_commit: SHA } })
    expect((await d.findDispatchedRun('equipe/app', 'deploy.yml', since))?.runId).toBe('9')
    expect(await d.runStatus('equipe/app', '9')).toMatchObject({ state: 'succeeded' })
    await expect(d.dispatchWorkflow('equipe/app', '../x.yml', 'main', {})).rejects.toThrow()
    await expect(d.dispatchWorkflow('equipe/app', 'deploy.yml', 'main', { 'Bad-Key': 'x' })).rejects.toThrow()
    await expect(d.dispatchWorkflow('equipe/app', 'deploy.yml', 'main', { scanoria_tag: 'a\nb' })).rejects.toThrow()
  })

  it('lecture, commit par fichier, PR, fusion automatique liée au commit', async () => {
    const calls = fake([
      ['GET', /\/contents\/apps\/app\.yaml\?ref=main$/, () => [200, { type: 'file', content: b64('image: x\n'), sha: 'f1', size: 9 }]],
      ['GET', /\/contents\/apps\/gros\.yaml/, () => [200, { type: 'file', content: b64('x'), size: 10_000_000 }]],
      ['GET', /\/contents\/apps\/dossier/, () => [200, { type: 'dir' }]],
      ['GET', /\/git\/ref\/heads\/main$/, () => [200, { object: { sha: SHA } }]],
      ['POST', /\/git\/refs$/, () => [201, {}]],
      ['PUT', /\/contents\/apps\/app\.yaml$/, () => [200, { commit: { sha: HEAD } }]],
      ['POST', /\/pulls$/, () => [201, { number: 5, html_url: 'https://github.com/equipe/deploiement/pull/5' }]],
      ['GET', /\/pulls\/5$/, () => [200, { body: '/scanoria auto-merge', state: 'open', node_id: 'PR_kw5', head: { sha: HEAD } }]],
      ['GET', /\/pulls\/6$/, () => [200, { body: null, state: 'closed', node_id: 'bad id!' }]],
      ['POST', /^\/graphql$/, c => [200, (c.body as { variables: { head: string } }).variables.head === HEAD ? { data: {} } : { errors: [{}] }]],
    ])
    const d = gh()
    expect(await d.readFile('equipe/deploiement', 'main', 'apps/app.yaml', 1000)).toEqual({ content: 'image: x\n', sha: 'f1' })
    expect(await d.readFile('equipe/deploiement', 'main', 'apps/absent.yaml', 1000)).toBeNull()
    expect(await d.readFile('equipe/deploiement', 'main', 'apps/dossier', 1000)).toBeNull()
    await expect(d.readFile('equipe/deploiement', 'main', 'apps/gros.yaml', 1000)).rejects.toThrow()
    expect(await d.commitFiles('equipe/deploiement', 'main', 'scanoria/promote/x', 'Promotion', [{ path: 'apps/app.yaml', content: 'image: y\n', sha: 'f1' }])).toBe(HEAD)
    expect(calls.find(c => c.method === 'POST' && c.url.endsWith('/git/refs'))!.body).toEqual({ ref: 'refs/heads/scanoria/promote/x', sha: SHA })
    const pr = await d.openPullRequest('equipe/deploiement', { head: 'scanoria/promote/x', base: 'main', title: 'Promotion', body: 'Voir ![img](https://ailleurs.exemple.test/x.png) @equipe' })
    expect(pr).toEqual({ number: 5, url: 'https://github.com/equipe/deploiement/pull/5' })
    const body = (calls.find(c => c.url.endsWith('/pulls') && c.method === 'POST')!.body as { body: string }).body
    expect(body).not.toContain('![img]')
    expect(body).not.toMatch(/(^|\s)@equipe/)
    expect(await d.pullRequestInfo('equipe/deploiement', 5)).toEqual({ body: '/scanoria auto-merge', open: true, nodeId: 'PR_kw5', headSha: HEAD })
    expect(await d.pullRequestInfo('equipe/deploiement', 6)).toEqual({ body: '', open: false, nodeId: null, headSha: null })
    expect(await d.enableAutoMerge('equipe/deploiement', 5, HEAD)).toBe('enabled')
    expect(await d.enableAutoMerge('equipe/deploiement', 5, SHA)).toBe('unsupported')
    expect(await d.enableAutoMerge('equipe/deploiement', 6, HEAD)).toBe('unsupported')
    expect(calls.filter(c => c.url.includes('/merge'))).toHaveLength(0)
  })

  it('GitHub Enterprise : GraphQL sur l\'instance', async () => {
    const calls = fake([
      ['GET', /\/pulls\/5$/, () => [200, { state: 'open', node_id: 'PR_1', head: { sha: HEAD } }]],
      ['POST', /\/api\/graphql$/, () => [200, { data: {} }]],
    ])
    const d = forgeDeployer({ kind: 'github', base_url: 'https://ghe.exemple.test', token: fakeToken() }, { consoleUrl: null })
    expect(await d.enableAutoMerge('equipe/deploiement', 5, HEAD)).toBe('enabled')
    expect(calls.at(-1)!.url).toBe('https://ghe.exemple.test/api/graphql')
  })
})

describe('GitLab', () => {
  const gl = () => forgeDeployer({ kind: 'gitlab', base_url: 'https://gitlab.exemple.test', token: fakeToken() }, { consoleUrl: null })

  it('pipeline déclenché par jeton de déclenchement, suivi', async () => {
    const trigger = fakeToken()
    const calls = fake([
      ['POST', /\/trigger\/pipeline$/, () => [201, { id: 77, web_url: 'https://gitlab.exemple.test/equipe/app/-/pipelines/77' }]],
      ['GET', /\/pipelines\/77$/, () => [200, { status: 'failed', web_url: 'https://gitlab.exemple.test/equipe/app/-/pipelines/77' }]],
    ])
    const d = gl()
    await expect(d.dispatchWorkflow('equipe/app', 'x.yml', 'main', {})).rejects.toThrow()
    expect(await d.dispatchWorkflow('equipe/app', 'x.yml', 'v1.0.0', { scanoria_commit: SHA }, trigger)).toMatchObject({ runId: '77' })
    expect(calls[0]!.body).toEqual({ token: trigger, ref: 'v1.0.0', variables: { SCANORIA_COMMIT: SHA } })
    expect(await d.findDispatchedRun('equipe/app', 'x.yml', new Date())).toBeNull()
    expect(await d.runStatus('equipe/app', '77')).toMatchObject({ state: 'failed' })
  })

  it('lecture, commit unique, MR, fusion quand le pipeline passe, liée au commit', async () => {
    const calls = fake([
      ['GET', /\/repository\/files\/apps%2Fapp\.yaml\?ref=main$/, () => [200, { content: b64('image: x\n'), blob_id: 'f1', size: 9 }]],
      ['GET', /\/repository\/files\/apps%2Fgros\.yaml/, () => [200, { content: b64('x'), size: 10_000_000 }]],
      ['GET', /\/repository\/branches\/main$/, () => [200, { commit: { id: SHA } }]],
      ['POST', /\/repository\/commits$/, () => [201, { id: HEAD }]],
      ['POST', /\/merge_requests$/, () => [201, { iid: 3, web_url: 'https://gitlab.exemple.test/equipe/deploiement/-/merge_requests/3' }]],
      ['GET', /\/merge_requests\/3$/, () => [200, { description: 'x', state: 'opened', sha: HEAD }]],
      ['PUT', /\/merge_requests\/3\/merge$/, () => [200, {}]],
    ])
    const d = gl()
    expect(await d.readFile('equipe/deploiement', 'main', 'apps/app.yaml', 1000)).toEqual({ content: 'image: x\n', sha: 'f1' })
    expect(await d.readFile('equipe/deploiement', 'main', 'apps/absent.yaml', 1000)).toBeNull()
    await expect(d.readFile('equipe/deploiement', 'main', 'apps/gros.yaml', 1000)).rejects.toThrow()
    expect(await d.branchHead('equipe/deploiement', 'main')).toBe(SHA)
    expect(await d.commitFiles('equipe/deploiement', 'main', 'scanoria/promote/x', 'Promotion', [{ path: 'apps/app.yaml', content: 'image: y\n', sha: null }])).toBe(HEAD)
    expect(await d.openPullRequest('equipe/deploiement', { head: 'scanoria/promote/x', base: 'main', title: 'Promotion', body: 'Promotion' })).toMatchObject({ number: 3 })
    expect(await d.pullRequestInfo('equipe/deploiement', 3)).toEqual({ body: 'x', open: true, nodeId: null, headSha: HEAD })
    expect(await d.enableAutoMerge('equipe/deploiement', 3, HEAD)).toBe('enabled')
    expect(calls.at(-1)!.body).toMatchObject({ merge_when_pipeline_succeeds: true, sha: HEAD })
    await expect(d.enableAutoMerge('equipe/deploiement', 3, 'pas-un-commit')).rejects.toThrow()
  })
})

describe('états de run', () => {
  it('Forgejo et GitHub, GitLab', () => {
    expect(runStateOf('success', null)).toBe('succeeded')
    expect(runStateOf('completed', 'failure')).toBe('failed')
    expect(runStateOf('cancelled', null)).toBe('failed')
    expect(runStateOf('waiting', null)).toBe('running')
    expect(gitlabStateOf('success')).toBe('succeeded')
    expect(gitlabStateOf('canceled')).toBe('failed')
    expect(gitlabStateOf('running')).toBe('running')
  })

  it('forge inconnue refusée', () => {
    expect(() => forgeDeployer({ kind: 'svn' as never, base_url: 'https://svn.exemple.test' }, { consoleUrl: null })).toThrow()
  })
})
