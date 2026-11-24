// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Client Forgejo (API v1, compatible Gitea) : première forge intégrée (D4).

import { ForgeError, forgeGet, forgeGetJson, type ForgeRequest } from './http'
import {
  DEFAULT_FILE_BYTES, DEFAULT_TREE_ENTRIES, MAX_REPOS, checkCommit, checkFullName, checkPath, checkRef,
  encodePath, toRepo, type ForgeAccess, type ForgeClient, type ForgeRepo, type TreeEntry,
} from './types'

const PAGE = 50

export function forgejoClient(access: ForgeAccess): ForgeClient {
  const api = `${access.base_url}/api/v1`
  const req: ForgeRequest = { token: access.token, authScheme: 'token' }
  const repoUrl = (fullName: string) => `${api}/repos/${encodePath(checkFullName(fullName))}`

  async function pages<T>(url: (page: number) => string, pick: (data: unknown) => unknown[], max: number): Promise<T[]> {
    const out: T[] = []
    for (let page = 1; out.length < max; page++) {
      const { data } = await forgeGetJson(url(page), req)
      const items = pick(data)
      out.push(...(items as T[]))
      if (items.length < PAGE) break
    }
    return out.slice(0, max)
  }

  return {
    kind: 'forgejo',

    async check() {
      if (!access.token) {
        await forgeGetJson(`${api}/version`, req)
        return { login: null }
      }
      const { data } = await forgeGetJson<{ login?: unknown }>(`${api}/user`, req)
      return { login: typeof data?.login === 'string' ? data.login : null }
    },

    async listRepos() {
      // Avec un jeton : les dépôts accessibles au compte. Sans jeton : les
      // dépôts publics de l'instance (recherche paginée).
      const raw = access.token
        ? await pages<unknown>(p => `${api}/user/repos?limit=${PAGE}&page=${p}`, d => (Array.isArray(d) ? d : []), MAX_REPOS)
        : await pages<unknown>(p => `${api}/repos/search?limit=${PAGE}&page=${p}`,
            d => (Array.isArray((d as { data?: unknown })?.data) ? (d as { data: unknown[] }).data : []), MAX_REPOS)
      return raw.map(toRepo).filter((r): r is ForgeRepo => !!r)
    },

    async repo(fullName) {
      const { data } = await forgeGetJson(repoUrl(fullName), req)
      const repo = toRepo(data)
      if (!repo) throw new ForgeError('E_FORGE_RESPONSE')
      return repo
    },

    async branches(fullName) {
      const raw = await pages<{ name?: unknown }>(p => `${repoUrl(fullName)}/branches?limit=${PAGE}&page=${p}`,
        d => (Array.isArray(d) ? d : []), 1000)
      return raw.map(b => b?.name).filter((n): n is string => typeof n === 'string')
    },

    async latestCommit(fullName, branch) {
      const { data } = await forgeGetJson<{ commit?: { id?: unknown } }>(`${repoUrl(fullName)}/branches/${encodePath(checkRef(branch))}`, req)
      return checkCommit(data?.commit?.id)
    },

    async listTree(fullName, ref, opts = {}) {
      const max = opts.maxEntries ?? DEFAULT_TREE_ENTRIES
      const entries: TreeEntry[] = []
      let more = false
      // Forgejo pagine l'arbre récursif (truncated = d'autres pages suivent).
      for (let page = 1; page <= 100; page++) {
        const { data } = await forgeGetJson<{ tree?: unknown, truncated?: unknown }>(
          `${repoUrl(fullName)}/git/trees/${encodeURIComponent(checkRef(ref))}?recursive=true&per_page=1000&page=${page}`, req)
        const tree = Array.isArray(data?.tree) ? data.tree as { path?: unknown, type?: unknown, size?: unknown }[] : []
        for (const e of tree) {
          if (typeof e?.path !== 'string') continue
          entries.push({ path: e.path, type: e.type === 'tree' ? 'dir' : 'file', size: typeof e.size === 'number' ? e.size : null })
        }
        more = data?.truncated === true && tree.length > 0
        if (!more || entries.length >= max) break
      }
      const truncated = more || entries.length > max
      return { entries: entries.slice(0, max), truncated }
    },

    async readFile(fullName, ref, path, opts = {}) {
      const maxBytes = opts.maxBytes ?? DEFAULT_FILE_BYTES
      try {
        const res = await forgeGet(`${repoUrl(fullName)}/raw/${encodePath(checkPath(path))}?ref=${encodeURIComponent(checkRef(ref))}`,
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
