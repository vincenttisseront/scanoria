// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 42 (0.8, chantier C) : écritures de la PR d'intégration (J2) et de
// la protection de branche dans Forgejo, GitHub et GitLab.
// - La PR est ouverte depuis une branche propre (scanoria/integration-…),
//   avec des fichiers NOUVEAUX seulement (aucun fichier existant écrasé), sauf
//   l'ajout d'un include dans .gitlab-ci.yml, construit par l'appelant.
// - L'appliance ne fusionne jamais : aucune fonction de fusion ici.
// - La protection n'ajoute que des contextes requis à la règle existante
//   (rien n'est retiré ni assoupli) ; GitLab : « pipelines must succeed ».
// Tout texte publié (titre, description) passe par sanitizeForForge.

import { ForgeError, forgeGetJson, forgeSendJson, normalizeBaseUrl, withForgeRetry, type ForgeRequest } from './http'
import { githubApiBase } from './github'
import { gitlabApiBase, gitlabProjectId, gitlabRequest } from './gitlab'
import { checkFullName, checkPath, checkRef, encodePath, type ForgeAccess } from './types'
import { checkNumber } from './pr-types'
import { sanitizeForForge } from './sanitize'
import { statusDescription } from './client'

export interface IntegrationFile {
  path: string
  content: string
  /** GitLab seulement : .gitlab-ci.yml existant, contenu complet après l'ajout de l'include. */
  update?: boolean
}

export interface IntegrationPrInput {
  base: string
  branch: string
  title: string
  body: string
  message: string
  files: IntegrationFile[]
}

export interface IntegrationPr {
  number: number
  url: string | null
}

export type PrState = 'open' | 'merged' | 'closed'

export interface IntegrationWriter {
  kind: ForgeAccess['kind']
  openPullRequest: (repo: string, input: IntegrationPrInput) => Promise<IntegrationPr>
  pullRequestState: (repo: string, number: number) => Promise<PrState>
  /** Ajoute les contextes requis à la protection de `branch` (crée la règle si elle manque). */
  protectBranch: (repo: string, branch: string, contexts: string[]) => Promise<{ created: boolean }>
}

const CONTEXT_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/
const MAX_FILES = 10
const MAX_FILE_BYTES = 64 * 1024

function checkInput(input: IntegrationPrInput): void {
  checkRef(input.base)
  checkRef(input.branch)
  if (!input.branch.startsWith('scanoria/')) throw new ForgeError('E_FORGE_INPUT')
  if (!input.files.length || input.files.length > MAX_FILES) throw new ForgeError('E_FORGE_INPUT')
  for (const f of input.files) {
    checkPath(f.path)
    if (Buffer.byteLength(f.content, 'utf8') > MAX_FILE_BYTES) throw new ForgeError('E_FORGE_INPUT')
    if (f.update && f.path !== '.gitlab-ci.yml') throw new ForgeError('E_FORGE_INPUT')
  }
}

/** Forgejo et GitHub : fichiers nouveaux seulement. */
function createOnly(input: IntegrationPrInput): void {
  if (input.files.some(f => f.update)) throw new ForgeError('E_FORGE_INPUT')
}

function checkContexts(contexts: string[]): string[] {
  if (!contexts.length || contexts.length > 10 || contexts.some(c => !CONTEXT_RE.test(c))) throw new ForgeError('E_FORGE_INPUT')
  return [...new Set(contexts)]
}

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64')
const httpsUrl = (v: unknown): string | null => (typeof v === 'string' && v.startsWith('https://') && v.length <= 1024 ? v : null)

function forgejoWriter(access: ForgeAccess): IntegrationWriter {
  const api = `${access.base_url}/api/v1`
  const req: ForgeRequest = { token: access.token, authScheme: 'token' }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  return {
    kind: 'forgejo',
    async openPullRequest(repo, input) {
      createOnly(input)
      // ChangeFiles : branche et fichiers en un seul commit.
      await forgeSendJson(`${repoUrl(repo)}/contents`, req, {
        method: 'POST',
        json: {
          branch: input.base,
          new_branch: input.branch,
          message: input.message,
          files: input.files.map(f => ({ operation: 'create', path: f.path, content: b64(f.content) })),
        },
      })
      const { data } = await forgeSendJson<{ number?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/pulls`, req, {
        method: 'POST', json: { base: input.base, head: input.branch, title: input.title, body: input.body },
      })
      if (typeof data?.number !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
      return { number: data.number, url: httpsUrl(data.html_url) }
    },
    async pullRequestState(repo, number) {
      const { data } = await forgeGetJson<{ state?: unknown, merged?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      return data?.merged === true ? 'merged' : data?.state === 'open' ? 'open' : 'closed'
    },
    async protectBranch(repo, branch, contextsIn) {
      const contexts = checkContexts(contextsIn)
      checkRef(branch)
      const list = (await forgeGetJson<unknown[]>(`${repoUrl(repo)}/branch_protections`, req)).data
      const rule = (Array.isArray(list) ? list : []).find(r => (r as { rule_name?: unknown, branch_name?: unknown }).rule_name === branch
        || (r as { branch_name?: unknown }).branch_name === branch) as { rule_name?: string, branch_name?: string, status_check_contexts?: unknown } | undefined
      if (rule) {
        const existing = Array.isArray(rule.status_check_contexts) ? rule.status_check_contexts.filter((c): c is string => typeof c === 'string') : []
        await forgeSendJson(`${repoUrl(repo)}/branch_protections/${encodeURIComponent(rule.rule_name ?? rule.branch_name ?? branch)}`, req, {
          method: 'PATCH', json: { enable_status_check: true, status_check_contexts: [...new Set([...existing, ...contexts])] },
        })
        return { created: false }
      }
      await forgeSendJson(`${repoUrl(repo)}/branch_protections`, req, {
        method: 'POST', json: { rule_name: branch, branch_name: branch, enable_status_check: true, status_check_contexts: contexts },
      })
      return { created: true }
    },
  }
}

function githubWriter(access: ForgeAccess): IntegrationWriter {
  const api = githubApiBase(access.base_url)
  const req: ForgeRequest = {
    token: access.token,
    authScheme: 'Bearer',
    accept: 'application/vnd.github+json',
    headers: { 'x-github-api-version': '2022-11-28' },
  }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  return {
    kind: 'github',
    async openPullRequest(repo, input) {
      createOnly(input)
      const { data: ref } = await forgeGetJson<{ object?: { sha?: unknown } }>(`${repoUrl(repo)}/git/ref/heads/${encodePath(input.base)}`, req)
      const sha = ref?.object?.sha
      if (typeof sha !== 'string' || !/^[0-9a-f]{40,64}$/.test(sha)) throw new ForgeError('E_FORGE_RESPONSE')
      await forgeSendJson(`${repoUrl(repo)}/git/refs`, req, { method: 'POST', json: { ref: `refs/heads/${input.branch}`, sha } })
      for (const f of input.files) {
        await forgeSendJson(`${repoUrl(repo)}/contents/${encodePath(f.path)}`, req, {
          method: 'PUT',
          json: { message: input.message, content: b64(f.content), branch: input.branch },
        })
      }
      const { data } = await forgeSendJson<{ number?: unknown, html_url?: unknown }>(`${repoUrl(repo)}/pulls`, req, {
        method: 'POST', json: { base: input.base, head: input.branch, title: input.title, body: input.body, maintainer_can_modify: true },
      })
      if (typeof data?.number !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
      return { number: data.number, url: httpsUrl(data.html_url) }
    },
    async pullRequestState(repo, number) {
      const { data } = await forgeGetJson<{ state?: unknown, merged?: unknown, merged_at?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      return data?.merged === true || typeof data?.merged_at === 'string' ? 'merged' : data?.state === 'open' ? 'open' : 'closed'
    },
    async protectBranch(repo, branch, contextsIn) {
      const contexts = checkContexts(contextsIn)
      const url = `${repoUrl(repo)}/branches/${encodePath(checkRef(branch))}/protection`
      const existing = await forgeGetJson<unknown>(url, req).then(() => true).catch((err: unknown) => {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return false
        throw err
      })
      if (existing) {
        // Ajout aux contextes requis (crée la section si elle manque) : rien d'autre ne change.
        try {
          await forgeSendJson(`${url}/required_status_checks/contexts`, req, { method: 'POST', json: { contexts } })
        }
        catch (err) {
          if (!(err instanceof ForgeError) || err.code !== 'E_FORGE_NOT_FOUND') throw err
          await forgeSendJson(`${url}/required_status_checks`, req, { method: 'PATCH', json: { strict: false, contexts } })
        }
        return { created: false }
      }
      await forgeSendJson(url, req, {
        method: 'PUT',
        json: { required_status_checks: { strict: false, contexts }, enforce_admins: false, required_pull_request_reviews: null, restrictions: null },
      })
      return { created: true }
    },
  }
}

function gitlabWriter(access: ForgeAccess): IntegrationWriter {
  const api = gitlabApiBase(access.base_url)
  const req = gitlabRequest(access)
  const proj = (r: string) => `${api}/projects/${gitlabProjectId(r)}`
  return {
    kind: 'gitlab',
    async openPullRequest(repo, input) {
      await forgeSendJson(`${proj(repo)}/repository/commits`, req, {
        method: 'POST',
        json: {
          branch: input.branch,
          start_branch: input.base,
          commit_message: input.message,
          actions: input.files.map(f => ({ action: f.update ? 'update' : 'create', file_path: f.path, content: f.content })),
        },
      })
      const { data } = await forgeSendJson<{ iid?: unknown, web_url?: unknown }>(`${proj(repo)}/merge_requests`, req, {
        method: 'POST', json: { source_branch: input.branch, target_branch: input.base, title: input.title, description: input.body, remove_source_branch: true },
      })
      if (typeof data?.iid !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
      return { number: data.iid, url: httpsUrl(data.web_url) }
    },
    async pullRequestState(repo, number) {
      const { data } = await forgeGetJson<{ state?: unknown }>(`${proj(repo)}/merge_requests/${checkNumber(number)}`, req)
      return data?.state === 'merged' ? 'merged' : data?.state === 'opened' ? 'open' : 'closed'
    },
    async protectBranch(repo, _branch, contextsIn) {
      checkContexts(contextsIn)
      // GitLab CE n'a pas de statut externe requis : l'étape Scanoria est un
      // job du pipeline, exigé par « pipelines must succeed ».
      await forgeSendJson(proj(repo), req, { method: 'PUT', json: { only_allow_merge_if_pipeline_succeeds: true } })
      return { created: false }
    },
  }
}

/** Contrat 42 : écritures d'intégration (J2) d'une forge, avec textes nettoyés et reprises. */
export function integrationWriter(access: ForgeAccess, opts: { consoleUrl: string | null }): IntegrationWriter {
  const a = { ...access, base_url: normalizeBaseUrl(access.base_url) }
  const impl = a.kind === 'forgejo' ? forgejoWriter(a) : a.kind === 'github' ? githubWriter(a) : a.kind === 'gitlab' ? gitlabWriter(a) : null
  if (!impl) throw new ForgeError('E_FORGE_UNSUPPORTED')
  return {
    kind: impl.kind,
    openPullRequest: (repo, input) => {
      checkInput(input)
      // Pas de reprise automatique : une écriture partielle (branche créée) ne doit pas être rejouée.
      return impl.openPullRequest(repo, {
        ...input,
        title: statusDescription(input.title),
        message: statusDescription(input.message),
        body: sanitizeForForge(input.body, { consoleUrl: opts.consoleUrl }),
      })
    },
    pullRequestState: (repo, number) => withForgeRetry(() => impl.pullRequestState(repo, number)),
    protectBranch: (repo, branch, contexts) => impl.protectBranch(repo, branch, contexts),
  }
}
