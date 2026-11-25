// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client GitLab (API v4) : lecture des dépôts pour la découverte et la
// détection (contrat 3), avec un compte de service à jeton de portée réduite
// (read_api, read_repository, et api pour publier ; docs/FORGES.md).

import { ForgeError, forgeGet, forgeGetJson, type ForgeRequest } from './http'
import {
  DEFAULT_FILE_BYTES, DEFAULT_TREE_ENTRIES, MAX_REPOS, checkCommit, checkFullName, checkPath, checkRef,
  isSafeRef, type ForgeAccess, type ForgeClient, type ForgeRepo, type TreeEntry,
} from './types'

const PAGE = 100
const FULL_NAME_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/

export function gitlabApiBase(baseUrl: string): string {
  return `${baseUrl}/api/v4`
}

/** Identifiant d'un projet GitLab dans l'URL : chemin complet encodé. */
export function gitlabProjectId(fullName: string): string {
  return encodeURIComponent(checkFullName(fullName))
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

export function gitlabToRepo(raw: unknown): ForgeRepo | null {
  const r = raw as Record<string, unknown> | null
  const fullName = str(r?.path_with_namespace)
  const cloneUrl = str(r?.http_url_to_repo)
  if (!r || !fullName || !FULL_NAME_RE.test(fullName) || !cloneUrl || !cloneUrl.startsWith('https://')) return null
  const branch = str(r.default_branch)
  return {
    full_name: fullName,
    name: str(r.path) ?? fullName.split('/').pop()!,
    description: str(r.description)?.slice(0, 500) || null,
    private: r.visibility !== 'public',
    archived: r.archived === true,
    fork: !!r.forked_from_project,
    empty: r.empty_repo === true,
    default_branch: branch && isSafeRef(branch) ? branch : null,
    clone_url: cloneUrl,
    ssh_url: str(r.ssh_url_to_repo),
    html_url: str(r.web_url),
  }
}

export function gitlabRequest(access: ForgeAccess): ForgeRequest {
  return { token: access.token, authScheme: 'Bearer' }
}

export function gitlabClient(access: ForgeAccess): ForgeClient {
  const api = gitlabApiBase(access.base_url)
  const req = gitlabRequest(access)
  const proj = (fullName: string) => `${api}/projects/${gitlabProjectId(fullName)}`

  async function pages<T>(url: (page: number) => string, max: number): Promise<T[]> {
    const out: T[] = []
    for (let page = 1; out.length < max && page <= 200; page++) {
      const { data } = await forgeGetJson(url(page), req)
      const items = Array.isArray(data) ? data as T[] : []
      out.push(...items)
      if (items.length < PAGE) break
    }
    return out.slice(0, max)
  }

  return {
    kind: 'gitlab',

    async check() {
      if (!access.token) {
        await forgeGetJson(`${api}/version`, req).catch(async (err: unknown) => {
          // /version exige un jeton : l'accès anonyme se vérifie sur les projets publics.
          if (!(err instanceof ForgeError) || err.code !== 'E_FORGE_AUTH') throw err
          await forgeGetJson(`${api}/projects?per_page=1`, req)
        })
        return { login: null }
      }
      const { data } = await forgeGetJson<{ username?: unknown }>(`${api}/user`, req)
      return { login: typeof data?.username === 'string' ? data.username : null }
    },

    async listRepos() {
      const filter = access.token ? 'membership=true' : 'visibility=public'
      const raw = await pages<unknown>(p => `${api}/projects?${filter}&archived=false&simple=false&per_page=${PAGE}&page=${p}`, MAX_REPOS)
      return raw.map(gitlabToRepo).filter((r): r is ForgeRepo => !!r)
    },

    async repo(fullName) {
      const { data } = await forgeGetJson(proj(fullName), req)
      const repo = gitlabToRepo(data)
      if (!repo) throw new ForgeError('E_FORGE_RESPONSE')
      return repo
    },

    async branches(fullName) {
      const raw = await pages<{ name?: unknown }>(p => `${proj(fullName)}/repository/branches?per_page=${PAGE}&page=${p}`, 1000)
      return raw.map(b => b?.name).filter((n): n is string => typeof n === 'string')
    },

    async latestCommit(fullName, branch) {
      const { data } = await forgeGetJson<{ commit?: { id?: unknown } }>(`${proj(fullName)}/repository/branches/${encodeURIComponent(checkRef(branch))}`, req)
      return checkCommit(data?.commit?.id)
    },

    async listTree(fullName, ref, opts = {}) {
      const max = opts.maxEntries ?? DEFAULT_TREE_ENTRIES
      const entries: TreeEntry[] = []
      let more = false
      for (let page = 1; page <= 200; page++) {
        const { data } = await forgeGetJson(`${proj(fullName)}/repository/tree?recursive=true&ref=${encodeURIComponent(checkRef(ref))}&per_page=${PAGE}&page=${page}`, req)
        const items = Array.isArray(data) ? data as { path?: unknown, type?: unknown }[] : []
        for (const e of items) {
          if (typeof e?.path === 'string') entries.push({ path: e.path, type: e.type === 'tree' ? 'dir' : 'file', size: null })
        }
        more = items.length === PAGE
        if (!more || entries.length >= max) break
      }
      return { entries: entries.slice(0, max), truncated: more || entries.length > max }
    },

    async readFile(fullName, ref, path, opts = {}) {
      const maxBytes = opts.maxBytes ?? DEFAULT_FILE_BYTES
      try {
        const res = await forgeGet(`${proj(fullName)}/repository/files/${encodeURIComponent(checkPath(path))}/raw?ref=${encodeURIComponent(checkRef(ref))}`,
          { ...req, accept: '*/*', maxBytes }, { allowNotFound: true })
        return res.status === 404 ? null : res.body.toString('utf8')
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_TOO_LARGE') return null
        throw err
      }
    },
  }
}
