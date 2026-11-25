// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client GitHub (REST v3) : github.com (api.github.com) ou GitHub Enterprise
// Server (<base>/api/v3).

import { ForgeError, forgeGet, forgeGetJson, type ForgeRequest } from './http'
import {
  DEFAULT_FILE_BYTES, DEFAULT_TREE_ENTRIES, MAX_REPOS, checkCommit, checkFullName, checkPath, checkRef,
  encodePath, toRepo, type ForgeAccess, type ForgeClient, type ForgeRepo,
} from './types'

const PAGE = 100

export function githubApiBase(baseUrl: string): string {
  const u = new URL(baseUrl)
  if (u.hostname === 'github.com' || u.hostname === 'www.github.com') return 'https://api.github.com'
  if (u.hostname === 'api.github.com' || u.pathname.endsWith('/api/v3')) return baseUrl
  return `${baseUrl}/api/v3`
}

export function githubClient(access: ForgeAccess): ForgeClient {
  const api = githubApiBase(access.base_url)
  const req: ForgeRequest = {
    token: access.token,
    authScheme: 'Bearer',
    accept: 'application/vnd.github+json',
    headers: { 'x-github-api-version': '2022-11-28' },
  }
  const repoUrl = (fullName: string) => `${api}/repos/${encodePath(checkFullName(fullName))}`

  async function pages<T>(url: (page: number) => string, max: number): Promise<T[]> {
    const out: T[] = []
    for (let page = 1; out.length < max; page++) {
      const { data } = await forgeGetJson(url(page), req)
      const items = Array.isArray(data) ? data as T[] : []
      out.push(...items)
      if (items.length < PAGE) break
    }
    return out.slice(0, max)
  }

  return {
    kind: 'github',

    async check() {
      if (!access.token) {
        await forgeGetJson(`${api}/rate_limit`, req)
        return { login: null }
      }
      const { data } = await forgeGetJson<{ login?: unknown }>(`${api}/user`, req)
      return { login: typeof data?.login === 'string' ? data.login : null }
    },

    async listRepos() {
      // Sans jeton, GitHub ne permet pas de lister « ses » dépôts : un dépôt
      // public s'ajoute alors par son nom.
      if (!access.token) return []
      if (access.installation) {
        // Application GitHub (J1) : dépôts accordés à l'installation.
        const out: unknown[] = []
        for (let page = 1; out.length < MAX_REPOS; page++) {
          const { data } = await forgeGetJson<{ repositories?: unknown }>(`${api}/installation/repositories?per_page=${PAGE}&page=${page}`, req)
          const items = Array.isArray(data?.repositories) ? data.repositories : []
          out.push(...items)
          if (items.length < PAGE) break
        }
        return out.slice(0, MAX_REPOS).map(toRepo).filter((r): r is ForgeRepo => !!r)
      }
      const raw = await pages<unknown>(p => `${api}/user/repos?per_page=${PAGE}&page=${p}&sort=full_name`, MAX_REPOS)
      return raw.map(toRepo).filter((r): r is ForgeRepo => !!r)
    },

    async repo(fullName) {
      const { data } = await forgeGetJson(repoUrl(fullName), req)
      const repo = toRepo(data)
      if (!repo) throw new ForgeError('E_FORGE_RESPONSE')
      return repo
    },

    async branches(fullName) {
      const raw = await pages<{ name?: unknown }>(p => `${repoUrl(fullName)}/branches?per_page=${PAGE}&page=${p}`, 1000)
      return raw.map(b => b?.name).filter((n): n is string => typeof n === 'string')
    },

    async latestCommit(fullName, branch) {
      const { data } = await forgeGetJson<{ commit?: { sha?: unknown } }>(`${repoUrl(fullName)}/branches/${encodePath(checkRef(branch))}`, req)
      return checkCommit(data?.commit?.sha)
    },

    async listTree(fullName, ref, opts = {}) {
      const max = opts.maxEntries ?? DEFAULT_TREE_ENTRIES
      const res = await forgeGet(`${repoUrl(fullName)}/git/trees/${encodeURIComponent(checkRef(ref))}?recursive=1`, req, { allowNotFound: true })
      if (res.status === 404) throw new ForgeError('E_FORGE_NOT_FOUND', 404)
      let data: { tree?: unknown, truncated?: unknown }
      try {
        data = JSON.parse(res.body.toString('utf8'))
      }
      catch {
        throw new ForgeError('E_FORGE_RESPONSE', res.status)
      }
      const tree = Array.isArray(data?.tree) ? data.tree as { path?: unknown, type?: unknown, size?: unknown }[] : []
      const entries = tree
        .filter(e => typeof e?.path === 'string' && (e.type === 'blob' || e.type === 'tree'))
        .map(e => ({ path: e.path as string, type: e.type === 'tree' ? 'dir' as const : 'file' as const, size: typeof e.size === 'number' ? e.size : null }))
      return { entries: entries.slice(0, max), truncated: data?.truncated === true || entries.length > max }
    },

    async readFile(fullName, ref, path, opts = {}) {
      const maxBytes = opts.maxBytes ?? DEFAULT_FILE_BYTES
      try {
        const res = await forgeGet(`${repoUrl(fullName)}/contents/${encodePath(checkPath(path))}?ref=${encodeURIComponent(checkRef(ref))}`,
          { ...req, accept: 'application/vnd.github.raw', maxBytes }, { allowNotFound: true })
        return res.status === 404 ? null : res.body.toString('utf8')
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_TOO_LARGE') return null
        throw err
      }
    },
  }
}
