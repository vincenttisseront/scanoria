// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Faux serveurs Forgejo et GitHub en Node pour les tests (chantier A). Ils
// sont servis en clair sur 127.0.0.1 ; setForgeTransport redirige les URL
// logiques https://<hôte>.exemple.test vers eux, après les contrôles d'URL.
// Comportements simulés : pagination, 401, 404, 429, réponse énorme,
// redirection vers un autre hôte, arbre de dépôt et fichiers.

import { randomBytes, randomInt } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { setForgeTransport } from '../../server/forges/http'

/** Jeton de test manifestement faux, généré à l'exécution (aucun motif connu). */
export function fakeToken(): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  return `scn_${Array.from({ length: 40 }, () => alphabet[randomInt(alphabet.length)]).join('')}`
}

export interface FakeRepo {
  full_name: string
  default_branch: string
  private?: boolean
  archived?: boolean
  empty?: boolean
  branches?: Record<string, string>
  files?: Record<string, string>
}

export interface FakeForge {
  kind: 'forgejo' | 'github'
  host: string
  token: string
  login: string
  repos: FakeRepo[]
  /** Chemins (préfixe) → comportement forcé. */
  faults: Map<string, 'rate' | 'huge' | 'redirect-other' | 'redirect-same' | 'server' | 'slow'>
  requests: { path: string, auth: string | null }[]
}

export function fakeSha(): string {
  return randomBytes(20).toString('hex')
}

export function newFakeForge(kind: 'forgejo' | 'github', host: string, repos: FakeRepo[]): FakeForge {
  return {
    kind, host, token: fakeToken(), login: 'robot', repos: repos.map(r => ({
      ...r, branches: r.branches ?? { [r.default_branch]: fakeSha() }, files: r.files ?? {},
    })), faults: new Map(), requests: [],
  }
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body)
  res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json', ...headers })
  res.end(text)
}

function repoJson(f: FakeForge, r: FakeRepo) {
  return {
    full_name: r.full_name, name: r.full_name.split('/').pop(), description: 'dépôt de test', private: !!r.private,
    archived: !!r.archived, fork: false, empty: !!r.empty, default_branch: r.default_branch,
    clone_url: `https://${f.host}/${r.full_name}.git`, ssh_url: `git@${f.host}:${r.full_name}.git`, html_url: `https://${f.host}/${r.full_name}`,
  }
}

function tree(r: FakeRepo) {
  const dirs = new Set<string>()
  for (const p of Object.keys(r.files ?? {})) {
    const parts = p.split('/')
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'))
  }
  return [
    ...[...dirs].map(d => ({ path: d, type: 'tree', size: 0 })),
    ...Object.entries(r.files ?? {}).map(([path, content]) => ({ path, type: 'blob', size: content.length })),
  ]
}

function handle(f: FakeForge, req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `https://${f.host}`)
  const auth = req.headers.authorization ?? null
  f.requests.push({ path: url.pathname + url.search, auth })
  for (const [prefix, fault] of f.faults) {
    if (!url.pathname.startsWith(prefix)) continue
    if (fault === 'rate') return send(res, f.kind === 'github' ? 403 : 429, { message: 'rate' }, f.kind === 'github' ? { 'x-ratelimit-remaining': '0' } : {})
    if (fault === 'huge') {
      res.writeHead(200, { 'content-type': 'application/json' })
      const chunk = Buffer.alloc(1024 * 1024, 0x20)
      for (let i = 0; i < 12; i++) res.write(chunk)
      return res.end('[]')
    }
    if (fault === 'redirect-other') return send(res, 302, '', { location: 'https://autre.exemple.test/api/v1/user' })
    if (fault === 'redirect-same') {
      f.faults.delete(prefix)
      return send(res, 301, '', { location: url.pathname + url.search })
    }
    if (fault === 'server') return send(res, 500, { message: 'boom' })
    if (fault === 'slow') return setTimeout(() => send(res, 200, {}), 3000)
  }
  const expected = f.kind === 'github' ? `Bearer ${f.token}` : `token ${f.token}`
  const anonymous = auth === null
  if (!anonymous && auth !== expected) return send(res, 401, { message: 'bad credentials' })

  const prefix = f.kind === 'github' ? '' : '/api/v1'
  const p = url.pathname.startsWith(prefix) ? url.pathname.slice(prefix.length) : url.pathname
  const visible = f.repos.filter(r => !anonymous || !r.private)
  const page = Number(url.searchParams.get('page') ?? '1')
  const limit = Number(url.searchParams.get(f.kind === 'github' ? 'per_page' : 'limit') ?? '30')
  const paginate = <T>(items: T[]) => items.slice((page - 1) * limit, page * limit)

  if (p === '/version' || p === '/rate_limit') return send(res, 200, { version: '1.0.0' })
  if (p === '/user') return anonymous ? send(res, 401, {}) : send(res, 200, { login: f.login })
  if (p === '/user/repos') return anonymous ? send(res, 401, {}) : send(res, 200, paginate(visible.map(r => repoJson(f, r))))
  if (p === '/repos/search') return send(res, 200, { ok: true, data: paginate(visible.filter(r => !r.private).map(r => repoJson(f, r))) })

  const m = /^\/repos\/([^/]+\/[^/]+?)(\/.*)?$/.exec(p)
  const repo = m ? visible.find(r => r.full_name === decodeURIComponent(m[1]!)) : undefined
  if (!m || !repo) return send(res, 404, { message: 'not found' })
  const rest = m[2] ?? ''
  if (!rest) return send(res, 200, repoJson(f, repo))
  // Analyses de PR (0.7) : aucune PR ouverte sur cette fausse forge en lecture.
  if (rest === '/pulls') return send(res, 200, [])
  if (rest === '/branches') {
    return send(res, 200, paginate(Object.entries(repo.branches!).map(([name, id]) => ({ name, commit: f.kind === 'github' ? { sha: id } : { id } }))))
  }
  const branch = /^\/branches\/(.+)$/.exec(rest)
  if (branch) {
    const id = repo.branches![decodeURIComponent(branch[1]!)]
    if (!id) return send(res, 404, {})
    return send(res, 200, { name: branch[1], commit: f.kind === 'github' ? { sha: id } : { id } })
  }
  if (/^\/git\/trees\//.test(rest)) {
    const all = tree(repo)
    if (f.kind === 'github') return send(res, 200, { sha: 'x', tree: all, truncated: false })
    const perPage = Number(url.searchParams.get('per_page') ?? '1000')
    const items = all.slice((page - 1) * perPage, page * perPage)
    return send(res, 200, { sha: 'x', tree: items, truncated: page * perPage < all.length, page, total_count: all.length })
  }
  const raw = f.kind === 'github' ? /^\/contents\/(.+)$/.exec(rest) : /^\/raw\/(.+)$/.exec(rest)
  if (raw) {
    const content = repo.files![decodeURIComponent(raw[1]!)]
    return content === undefined ? send(res, 404, {}) : send(res, 200, content)
  }
  return send(res, 404, {})
}

export interface FakeForgeServer {
  forges: Map<string, FakeForge>
  close: () => Promise<void>
}

/**
 * Démarre un serveur unique pour plusieurs fausses forges (aiguillées par
 * l'hôte logique) et installe le transport de test.
 */
export async function startFakeForges(forges: FakeForge[]): Promise<FakeForgeServer> {
  const byHost = new Map(forges.map(f => [f.host, f]))
  const server: Server = createServer((req, res) => {
    const host = String(req.headers['x-fake-host'] ?? '')
    const f = byHost.get(host)
    if (!f) return send(res, 502, { message: 'unknown host' })
    handle(f, req, res)
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  setForgeTransport(async (url, init) => {
    const u = new URL(url)
    const host = u.hostname === 'api.github.com' ? 'github.com' : u.hostname
    if (!byHost.has(host)) throw new TypeError('fetch failed')
    const headers = new Headers(init.headers as HeadersInit)
    headers.set('x-fake-host', host)
    return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, { ...init, headers })
  })
  return {
    forges: byHost,
    close: async () => {
      setForgeTransport()
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    },
  }
}
