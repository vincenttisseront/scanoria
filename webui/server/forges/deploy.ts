// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 42 (0.8, chantier D) : écritures de déploiement dans une forge, en
// ajout au client du contrat 30. L'appliance déclenche, propose ou promeut ;
// elle ne fusionne jamais une PR et ne détient aucun accès à la production :
// - J11 : déclenchement d'un workflow (workflow_dispatch Forgejo ou GitHub,
//   déclencheur de pipeline GitLab) et lecture de son état ;
// - J12 : branche, commit des seuls fichiers désignés, PR de promotion ;
// - J12, J16 : activation de la fusion automatique NATIVE de la forge
//   (« fusionner quand les contrôles passent »), jamais une fusion directe.
// Tout texte publié passe par sanitizeForForge ; délais, tailles et
// redirections sont ceux de http.ts.

import { ForgeError, forgeGetJson, forgeSendJson, normalizeBaseUrl, withForgeRetry, type ForgeRequest } from './http'
import { checkCommit, checkFullName, checkPath, checkRef, encodePath, type ForgeAccess } from './types'
import { checkNumber } from './pr-types'
import { githubApiBase } from './github'
import { gitlabApiBase, gitlabProjectId, gitlabRequest } from './gitlab'
import { sanitizeForForge } from './sanitize'
import { statusDescription } from './client'

export type RunState = 'running' | 'succeeded' | 'failed'

export interface DispatchResult {
  /** Identifiant du run ou du pipeline, quand la forge le rend. */
  runId: string | null
  url: string | null
}

export interface RunStatus {
  state: RunState
  url: string | null
}

export interface RepoFile {
  content: string
  /** Identifiant de version du fichier (sha du blob), pour une mise à jour sans écrasement. */
  sha: string | null
}

export interface FileChange {
  path: string
  content: string
  sha: string | null
}

export interface OpenedPullRequest {
  number: number
  url: string | null
}

export interface ForgeDeployer {
  kind: ForgeAccess['kind']
  dispatchWorkflow: (repo: string, workflow: string, ref: string, inputs: Record<string, string>, triggerToken?: string | null) => Promise<DispatchResult>
  /** Dernier run déclenché à la main pour ce workflow depuis `since` (GitHub sans identifiant de run). */
  findDispatchedRun: (repo: string, workflow: string, since: Date) => Promise<DispatchResult | null>
  runStatus: (repo: string, runId: string) => Promise<RunStatus>
  readFile: (repo: string, ref: string, path: string, maxBytes: number) => Promise<RepoFile | null>
  branchHead: (repo: string, branch: string) => Promise<string>
  /** Crée `branch` depuis `base` avec les fichiers modifiés (un seul commit). */
  commitFiles: (repo: string, base: string, branch: string, message: string, files: FileChange[]) => Promise<void>
  openPullRequest: (repo: string, pr: { head: string, base: string, title: string, body: string }) => Promise<OpenedPullRequest>
  /** Description et état d'une PR (J16 : demande de l'auteur dans la description). */
  pullRequestInfo: (repo: string, number: number) => Promise<{ body: string, open: boolean, nodeId: string | null }>
  /** Fusion automatique native de la forge ; « unsupported » si la forge ne la permet pas. */
  enableAutoMerge: (repo: string, number: number) => Promise<'enabled' | 'unsupported'>
}

export const WORKFLOW_RE = /^[A-Za-z0-9._-]{1,100}\.ya?ml$/
const INPUT_KEY_RE = /^[a-z][a-z0-9_]{0,63}$/
const RUN_ID_RE = /^\d{1,19}$/
export const MAX_GITOPS_FILE_BYTES = 256 * 1024

function checkWorkflow(w: string): string {
  if (!WORKFLOW_RE.test(w)) throw new ForgeError('E_FORGE_INPUT')
  return w
}

function checkInputs(inputs: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(inputs)) {
    // eslint-disable-next-line no-control-regex
    if (!INPUT_KEY_RE.test(k) || typeof v !== 'string' || v.length > 500 || /[\u0000-\u001F]/.test(v)) throw new ForgeError('E_FORGE_INPUT')
    out[k] = v
  }
  return out
}

function checkRunId(id: string): string {
  if (!RUN_ID_RE.test(id)) throw new ForgeError('E_FORGE_INPUT')
  return id
}

const httpsUrl = (v: unknown): string | null => (typeof v === 'string' && v.startsWith('https://') && v.length <= 500 ? v : null)

function b64(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64')
}

function fromB64(v: unknown, maxBytes: number): string | null {
  if (typeof v !== 'string') return null
  const buf = Buffer.from(v.replace(/\s+/g, ''), 'base64')
  if (buf.length > maxBytes) throw new ForgeError('E_FORGE_TOO_LARGE')
  return buf.toString('utf8')
}

/** État d'un run Forgejo ou GitHub (status, conclusion). */
export function runStateOf(status: unknown, conclusion: unknown): RunState {
  const s = typeof status === 'string' ? status : ''
  const c = typeof conclusion === 'string' ? conclusion : ''
  if (s === 'success' || (s === 'completed' && c === 'success')) return 'succeeded'
  if (['failure', 'cancelled', 'skipped', 'blocked'].includes(s) || (s === 'completed' && c !== 'success')) return 'failed'
  return 'running'
}

/** État d'un pipeline GitLab. */
export function gitlabStateOf(status: unknown): RunState {
  if (status === 'success') return 'succeeded'
  if (['failed', 'canceled', 'skipped'].includes(String(status))) return 'failed'
  return 'running'
}

function forgejoDeployer(access: ForgeAccess): ForgeDeployer {
  const api = `${access.base_url}/api/v1`
  const req: ForgeRequest = { token: access.token, authScheme: 'token' }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  return {
    kind: 'forgejo',
    async dispatchWorkflow(repo, workflow, ref, inputs) {
      const { data } = await forgeSendJson<{ id?: unknown, html_url?: unknown }>(
        `${repoUrl(repo)}/actions/workflows/${encodeURIComponent(checkWorkflow(workflow))}/dispatches`, req,
        { method: 'POST', json: { ref: checkRef(ref), inputs: checkInputs(inputs), return_run_info: true } })
      const id = typeof data?.id === 'number' ? String(data.id) : null
      return { runId: id, url: httpsUrl(data?.html_url) ?? (id ? `${access.base_url}/${checkFullName(repo)}/actions/runs/${id}` : null) }
    },
    findDispatchedRun: async () => null,
    async runStatus(repo, runId) {
      const { data } = await forgeGetJson<{ status?: unknown, conclusion?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/actions/runs/${checkRunId(runId)}`, req)
      return { state: runStateOf(data?.status, data?.conclusion), url: httpsUrl(data?.html_url) }
    },
    async readFile(repo, ref, path, maxBytes) {
      try {
        const { data } = await forgeGetJson<{ type?: unknown, content?: unknown, sha?: unknown, size?: unknown }>(
          `${repoUrl(repo)}/contents/${encodePath(checkPath(path))}?ref=${encodeURIComponent(checkRef(ref))}`, req)
        if (data?.type !== 'file') return null
        if (typeof data.size === 'number' && data.size > maxBytes) throw new ForgeError('E_FORGE_TOO_LARGE')
        const content = fromB64(data.content, maxBytes)
        return content === null ? null : { content, sha: typeof data.sha === 'string' ? data.sha : null }
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return null
        throw err
      }
    },
    async branchHead(repo, branch) {
      const { data } = await forgeGetJson<{ commit?: { id?: unknown } }>(`${repoUrl(repo)}/branches/${encodeURIComponent(checkRef(branch))}`, req)
      return checkCommit(data?.commit?.id)
    },
    async commitFiles(repo, base, branch, message, files) {
      await forgeSendJson(`${repoUrl(repo)}/contents`, req, {
        method: 'POST',
        json: {
          branch: checkRef(base),
          new_branch: checkRef(branch),
          message: statusDescription(message),
          files: files.map(f => ({ operation: 'update', path: checkPath(f.path), content: b64(f.content), ...(f.sha ? { sha: f.sha } : {}) })),
        },
      })
    },
    async openPullRequest(repo, pr) {
      const { data } = await forgeSendJson<{ number?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/pulls`, req, {
        method: 'POST', json: { head: checkRef(pr.head), base: checkRef(pr.base), title: statusDescription(pr.title), body: pr.body },
      })
      return { number: checkNumber(data?.number), url: httpsUrl(data?.html_url) }
    },
    async pullRequestInfo(repo, number) {
      const { data } = await forgeGetJson<{ body?: unknown, state?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      return { body: typeof data?.body === 'string' ? data.body : '', open: data?.state === 'open', nodeId: null }
    },
    async enableAutoMerge(repo, number) {
      // Forgejo : « fusionner quand les contrôles passent » ; c'est la forge qui
      // fusionne, une fois les contrôles requis au vert.
      await forgeSendJson(`${repoUrl(repo)}/pulls/${checkNumber(number)}/merge`, req, {
        method: 'POST', json: { Do: 'squash', merge_when_checks_succeed: true },
      })
      return 'enabled'
    },
  }
}

function githubDeployer(access: ForgeAccess): ForgeDeployer {
  const api = githubApiBase(access.base_url)
  const req: ForgeRequest = { token: access.token, authScheme: 'Bearer', accept: 'application/vnd.github+json', headers: { 'x-github-api-version': '2022-11-28' } }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  return {
    kind: 'github',
    async dispatchWorkflow(repo, workflow, ref, inputs) {
      const { data } = await forgeSendJson<{ workflow_run_id?: unknown, html_url?: unknown }>(
        `${repoUrl(repo)}/actions/workflows/${encodeURIComponent(checkWorkflow(workflow))}/dispatches`, req,
        { method: 'POST', json: { ref: checkRef(ref), inputs: checkInputs(inputs), return_run_details: true } })
      const id = typeof data?.workflow_run_id === 'number' ? String(data.workflow_run_id) : null
      return { runId: id, url: httpsUrl(data?.html_url) }
    },
    async findDispatchedRun(repo, workflow, since) {
      const { data } = await forgeGetJson<{ workflow_runs?: { id?: unknown, html_url?: unknown, created_at?: unknown }[] }>(
        `${repoUrl(repo)}/actions/workflows/${encodeURIComponent(checkWorkflow(workflow))}/runs?event=workflow_dispatch&per_page=5`, req)
      const run = (data?.workflow_runs ?? []).find(r => typeof r?.id === 'number' && Date.parse(String(r.created_at)) >= since.getTime() - 5000)
      return run ? { runId: String(run.id), url: httpsUrl(run.html_url) } : null
    },
    async runStatus(repo, runId) {
      const { data } = await forgeGetJson<{ status?: unknown, conclusion?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/actions/runs/${checkRunId(runId)}`, req)
      return { state: runStateOf(data?.status, data?.conclusion), url: httpsUrl(data?.html_url) }
    },
    async readFile(repo, ref, path, maxBytes) {
      try {
        const { data } = await forgeGetJson<{ type?: unknown, content?: unknown, sha?: unknown, size?: unknown }>(
          `${repoUrl(repo)}/contents/${encodePath(checkPath(path))}?ref=${encodeURIComponent(checkRef(ref))}`, req)
        if (data?.type !== 'file') return null
        if (typeof data.size === 'number' && data.size > maxBytes) throw new ForgeError('E_FORGE_TOO_LARGE')
        const content = fromB64(data.content, maxBytes)
        return content === null ? null : { content, sha: typeof data.sha === 'string' ? data.sha : null }
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return null
        throw err
      }
    },
    async branchHead(repo, branch) {
      const { data } = await forgeGetJson<{ object?: { sha?: unknown } }>(`${repoUrl(repo)}/git/ref/heads/${encodePath(checkRef(branch))}`, req)
      return checkCommit(data?.object?.sha)
    },
    async commitFiles(repo, base, branch, message, files) {
      const sha = await this.branchHead(repo, base)
      await forgeSendJson(`${repoUrl(repo)}/git/refs`, req, { method: 'POST', json: { ref: `refs/heads/${checkRef(branch)}`, sha } })
      for (const f of files) {
        await forgeSendJson(`${repoUrl(repo)}/contents/${encodePath(checkPath(f.path))}`, req, {
          method: 'PUT', json: { message: statusDescription(message), content: b64(f.content), branch, ...(f.sha ? { sha: f.sha } : {}) },
        })
      }
    },
    async openPullRequest(repo, pr) {
      const { data } = await forgeSendJson<{ number?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/pulls`, req, {
        method: 'POST', json: { head: checkRef(pr.head), base: checkRef(pr.base), title: statusDescription(pr.title), body: pr.body },
      })
      return { number: checkNumber(data?.number), url: httpsUrl(data?.html_url) }
    },
    async pullRequestInfo(repo, number) {
      const { data } = await forgeGetJson<{ body?: unknown, state?: unknown, node_id?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      const nodeId = typeof data?.node_id === 'string' && /^[A-Za-z0-9_=-]{1,100}$/.test(data.node_id) ? data.node_id : null
      return { body: typeof data?.body === 'string' ? data.body : '', open: data?.state === 'open', nodeId }
    },
    async enableAutoMerge(repo, number) {
      const info = await this.pullRequestInfo(repo, number)
      if (!info.nodeId) return 'unsupported'
      const graphql = access.base_url === 'https://github.com' || access.base_url === 'https://api.github.com'
        ? 'https://api.github.com/graphql'
        : `${access.base_url}/api/graphql`
      const { data } = await forgeSendJson<{ errors?: unknown[] }>(graphql, req, {
        method: 'POST',
        json: {
          query: 'mutation($id: ID!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, mergeMethod: SQUASH}) { clientMutationId } }',
          variables: { id: info.nodeId },
        },
      })
      // Fusion automatique désactivée dans les réglages du dépôt : rien n'est fusionné.
      return Array.isArray(data?.errors) && data.errors.length ? 'unsupported' : 'enabled'
    },
  }
}

function gitlabDeployer(access: ForgeAccess): ForgeDeployer {
  const api = gitlabApiBase(access.base_url)
  const req = gitlabRequest(access)
  const proj = (r: string) => `${api}/projects/${gitlabProjectId(r)}`
  return {
    kind: 'gitlab',
    async dispatchWorkflow(repo, _workflow, ref, inputs, triggerToken) {
      // Déclencheur de pipeline : jeton de déclenchement propre (deploy-token).
      if (!triggerToken) throw new ForgeError('E_FORGE_AUTH')
      const variables: Record<string, string> = {}
      for (const [k, v] of Object.entries(checkInputs(inputs))) variables[k.toUpperCase()] = v
      const { data } = await forgeSendJson<{ id?: unknown, web_url?: unknown }>(`${proj(repo)}/trigger/pipeline`, { authScheme: 'Bearer' }, {
        method: 'POST', json: { token: triggerToken, ref: checkRef(ref), variables },
      })
      return { runId: typeof data?.id === 'number' ? String(data.id) : null, url: httpsUrl(data?.web_url) }
    },
    findDispatchedRun: async () => null,
    async runStatus(repo, runId) {
      const { data } = await forgeGetJson<{ status?: unknown, web_url?: unknown }>(`${proj(repo)}/pipelines/${checkRunId(runId)}`, req)
      return { state: gitlabStateOf(data?.status), url: httpsUrl(data?.web_url) }
    },
    async readFile(repo, ref, path, maxBytes) {
      try {
        const { data } = await forgeGetJson<{ content?: unknown, blob_id?: unknown, size?: unknown }>(
          `${proj(repo)}/repository/files/${encodeURIComponent(checkPath(path))}?ref=${encodeURIComponent(checkRef(ref))}`, req)
        if (typeof data?.size === 'number' && data.size > maxBytes) throw new ForgeError('E_FORGE_TOO_LARGE')
        const content = fromB64(data?.content, maxBytes)
        return content === null ? null : { content, sha: typeof data?.blob_id === 'string' ? data.blob_id : null }
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return null
        throw err
      }
    },
    async branchHead(repo, branch) {
      const { data } = await forgeGetJson<{ commit?: { id?: unknown } }>(`${proj(repo)}/repository/branches/${encodeURIComponent(checkRef(branch))}`, req)
      return checkCommit(data?.commit?.id)
    },
    async commitFiles(repo, base, branch, message, files) {
      await forgeSendJson(`${proj(repo)}/repository/commits`, req, {
        method: 'POST',
        json: {
          branch: checkRef(branch),
          start_branch: checkRef(base),
          commit_message: statusDescription(message),
          actions: files.map(f => ({ action: 'update', file_path: checkPath(f.path), content: f.content })),
        },
      })
    },
    async openPullRequest(repo, pr) {
      const { data } = await forgeSendJson<{ iid?: unknown, web_url?: unknown }>(`${proj(repo)}/merge_requests`, req, {
        method: 'POST', json: { source_branch: checkRef(pr.head), target_branch: checkRef(pr.base), title: statusDescription(pr.title), description: pr.body },
      })
      return { number: checkNumber(data?.iid), url: httpsUrl(data?.web_url) }
    },
    async pullRequestInfo(repo, number) {
      const { data } = await forgeGetJson<{ description?: unknown, state?: unknown }>(`${proj(repo)}/merge_requests/${checkNumber(number)}`, req)
      return { body: typeof data?.description === 'string' ? data.description : '', open: data?.state === 'opened', nodeId: null }
    },
    async enableAutoMerge(repo, number) {
      await forgeSendJson(`${proj(repo)}/merge_requests/${checkNumber(number)}/merge`, req, {
        method: 'PUT', json: { merge_when_pipeline_succeeds: true, auto_merge: true, squash: true },
      })
      return 'enabled'
    },
  }
}

export interface DeployerOptions {
  consoleUrl: string | null
}

/** Contrat 42 : écritures de déploiement d'une forge (réessais sur erreur passagère, textes neutralisés). */
export function forgeDeployer(access: ForgeAccess, opts: DeployerOptions): ForgeDeployer {
  const a = { ...access, base_url: normalizeBaseUrl(access.base_url) }
  const impl = a.kind === 'forgejo' ? forgejoDeployer(a) : a.kind === 'github' ? githubDeployer(a) : a.kind === 'gitlab' ? gitlabDeployer(a) : null
  if (!impl) throw new ForgeError('E_FORGE_UNSUPPORTED')
  const clean = (md: string) => sanitizeForForge(md, { consoleUrl: opts.consoleUrl })
  return {
    kind: impl.kind,
    // Un déclenchement n'est jamais rejoué automatiquement : deux déploiements
    // pour une seule analyse seraient pires qu'un échec visible.
    dispatchWorkflow: (repo, workflow, ref, inputs, triggerToken) => impl.dispatchWorkflow(repo, workflow, ref, inputs, triggerToken),
    findDispatchedRun: (repo, workflow, since) => withForgeRetry(() => impl.findDispatchedRun(repo, workflow, since)),
    runStatus: (repo, runId) => withForgeRetry(() => impl.runStatus(repo, runId)),
    readFile: (repo, ref, path, maxBytes) => withForgeRetry(() => impl.readFile(repo, ref, path, Math.min(maxBytes, MAX_GITOPS_FILE_BYTES))),
    branchHead: (repo, branch) => withForgeRetry(() => impl.branchHead(repo, branch)),
    commitFiles: (repo, base, branch, message, files) => impl.commitFiles.call(impl, repo, base, branch, message, files),
    openPullRequest: (repo, pr) => impl.openPullRequest(repo, { ...pr, body: clean(pr.body) }),
    pullRequestInfo: (repo, number) => withForgeRetry(() => impl.pullRequestInfo.call(impl, repo, number)),
    enableAutoMerge: (repo, number) => impl.enableAutoMerge.call(impl, repo, number),
  }
}
