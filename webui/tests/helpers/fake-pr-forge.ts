// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Fausse forge en écriture pour les tests du chantier D (0.7) : Forgejo (API
// v1) avec PR, statuts, commentaires, revues, fichiers modifiés, commits et
// webhooks ; et la partie « application » de GitHub (conversion du
// manifeste, installation, jetons d'installation). Servie en clair sur
// 127.0.0.1 ; setForgeTransport redirige les URL logiques
// https://<hôte>.exemple.test vers elle. Chaque écriture est enregistrée.

import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { setForgeTransport } from '../../server/forges/http'
import { fakeSha, fakeToken } from './fake-forge'

export interface FakePr {
  number: number
  head: string
  head_ref: string
  base: string
  base_ref: string
  author: string
  files: string[]
}

export interface FakeComment { id: number, body: string, user: { login: string, type: string }, created_at: string }

export interface FakeRepoState {
  full_name: string
  archived: boolean
  prs: FakePr[]
  comments: Map<number, FakeComment[]>
  statuses: { sha: string, state: string, context: string, description: string, target_url?: string }[]
  reviews: { number: number, body: string, comments: { path: string, new_position: number, body: string }[] }[]
  hooks: { id: number, config: { url: string, secret: string }, events: string[] }[]
  authors: Record<string, { login: string, email: string }>
  /** Droits des collaborateurs (admin, write, read) ; un compte absent n'en a aucun (404). */
  permissions: Record<string, string>
  /** 0.8 (A) : tags, releases et fichiers joints (absents = aucun). */
  tags?: { name: string, sha: string }[]
  releases?: { id: number, tag_name: string, prerelease: boolean, assets: { name: string, size: number, body: Buffer }[] }[]
  /** 0.8 (A) : refuser l'envoi de fichiers (droit manquant, 403). */
  denyAssets?: boolean
}

export interface FakePrForge {
  host: string
  token: string
  login: string
  repos: Map<string, FakeRepoState>
  requests: { method: string, path: string }[]
  /** GitHub : application créée par conversion du manifeste. */
  app: { id: number, slug: string, pem: string, webhook_secret: string, installations: number[], codes: Set<string> }
  close: () => Promise<void>
}

let commentSeq = 1000

export function addRepo(f: FakePrForge, full_name: string, archived = false): FakeRepoState {
  const r: FakeRepoState = { full_name, archived, prs: [], comments: new Map(), statuses: [], reviews: [], hooks: [], authors: {}, permissions: {} }
  f.repos.set(full_name, r)
  return r
}

export function addPr(repo: FakeRepoState, p: Partial<FakePr> & { number: number }): FakePr {
  const pr: FakePr = { head: fakeSha(), head_ref: `feat/${p.number}`, base: fakeSha(), base_ref: 'main', author: 'dev-une', files: ['src/a.ts'], ...p }
  repo.prs = repo.prs.filter(x => x.number !== pr.number).concat(pr)
  repo.authors[pr.head] = { login: pr.author, email: `${pr.author}@exemple.test` }
  return pr
}

export function addComment(f: FakePrForge, repo: FakeRepoState, number: number, login: string, body: string, type = 'User'): FakeComment {
  const c: FakeComment = { id: commentSeq++, body, user: { login, type }, created_at: new Date().toISOString() }
  repo.comments.set(number, [...(repo.comments.get(number) ?? []), c])
  return c
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []
  for await (const c of req) chunks.push(c as Buffer)
  const text = Buffer.concat(chunks).toString('utf8')
  return text ? JSON.parse(text) as Record<string, unknown> : {}
}

function prJson(p: FakePr) {
  return { number: p.number, head: { sha: p.head, ref: p.head_ref }, base: { sha: p.base, ref: p.base_ref }, user: { login: p.author }, draft: false, state: 'open' }
}

async function handle(f: FakePrForge, req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `https://${f.host}`)
  const method = req.method ?? 'GET'
  f.requests.push({ method, path: url.pathname + url.search })
  // Forgejo (/api/v1) et GitHub Enterprise (/api/v3) : même aiguillage.
  const p = url.pathname.replace(/^\/api\/v[13](?=\/)/, '')

  // --- GitHub : application (JWT non vérifié ici ; la signature est testée à part).
  const conv = /^\/app-manifests\/([^/]+)\/conversions$/.exec(p)
  if (conv && method === 'POST') {
    if (!f.app.codes.delete(conv[1]!)) return send(res, 404, { message: 'code' })
    return send(res, 201, {
      id: f.app.id, slug: f.app.slug, client_id: 'Iv1.test', client_secret: randomBytes(20).toString('hex'),
      webhook_secret: f.app.webhook_secret, pem: f.app.pem, owner: { login: 'equipe' },
    })
  }
  const inst = /^\/app\/installations\/(\d+)(\/access_tokens)?$/.exec(p)
  if (inst) {
    if (!/^Bearer [\w-]+\.[\w-]+\.[\w-]+$/.test(req.headers.authorization ?? '')) return send(res, 401, {})
    const id = Number(inst[1])
    if (!f.app.installations.includes(id)) return send(res, 404, {})
    if (inst[2]) return send(res, 201, { token: f.token, expires_at: new Date(Date.now() + 3600_000).toISOString() })
    return send(res, 200, { id, app_id: f.app.id })
  }

  if (req.headers.authorization !== `token ${f.token}` && req.headers.authorization !== `Bearer ${f.token}`) return send(res, 401, { message: 'bad credentials' })
  const api = p
  if (api === '/version') return send(res, 200, { version: '11.0.0' })
  if (api === '/user') return send(res, 200, { login: f.login })
  if (api === '/user/repos' || api === '/installation/repositories') {
    const list = [...f.repos.values()].map(r => ({
      full_name: r.full_name, name: r.full_name.split('/')[1], private: true, archived: r.archived, empty: false, fork: false, default_branch: 'main',
      clone_url: `https://${f.host}/${r.full_name}.git`, html_url: `https://${f.host}/${r.full_name}`,
    }))
    const page = Number(url.searchParams.get('page') ?? '1')
    const items = page === 1 ? list : []
    return send(res, 200, api === '/installation/repositories' ? { repositories: items, total_count: list.length } : items)
  }
  const m = /^\/repos\/([^/]+\/[^/]+?)(\/.*)?$/.exec(api)
  const repo = m ? f.repos.get(decodeURIComponent(m[1]!)) : undefined
  if (!m || !repo) return send(res, 404, {})
  const rest = m[2] ?? ''
  // 0.8 (A) : tags, releases et fichiers joints (multipart, lu avant le JSON).
  if (rest === '/tags' && method === 'GET') {
    const page = Number(url.searchParams.get('page') ?? '1')
    return send(res, 200, page === 1 ? (repo.tags ?? []).map(t => ({ name: t.name, commit: { sha: t.sha } })) : [])
  }
  if (rest === '/releases' && method === 'GET') {
    const page = Number(url.searchParams.get('page') ?? '1')
    return send(res, 200, page === 1 ? (repo.releases ?? []).map(r => ({ id: r.id, tag_name: r.tag_name, prerelease: r.prerelease })) : [])
  }
  let y: RegExpExecArray | null
  if ((y = /^\/releases\/tags\/(.+)$/.exec(rest)) && method === 'GET') {
    const rel = (repo.releases ?? []).find(r => r.tag_name === decodeURIComponent(y![1]!))
    return rel ? send(res, 200, { id: rel.id, tag_name: rel.tag_name }) : send(res, 404, {})
  }
  if ((y = /^\/releases\/(\d+)\/assets$/.exec(rest))) {
    const rel = (repo.releases ?? []).find(r => r.id === Number(y![1]))
    if (!rel) return send(res, 404, {})
    if (method === 'GET') {
      const page = Number(url.searchParams.get('page') ?? '1')
      return send(res, 200, page === 1 ? rel.assets.map(a => ({ name: a.name, size: a.size })) : [])
    }
    if (repo.denyAssets) return send(res, 403, { message: 'forbidden' })
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    const raw = Buffer.concat(chunks)
    const name = url.searchParams.get('name') ?? ''
    const ct = String(req.headers['content-type'] ?? '')
    const boundary = /boundary=([^;]+)/.exec(ct)?.[1]
    if (!boundary || !raw.includes(Buffer.from(`--${boundary}--`))) return send(res, 400, { message: 'multipart' })
    const start = raw.indexOf('\r\n\r\n') + 4
    const end = raw.lastIndexOf(Buffer.from(`\r\n--${boundary}--`))
    rel.assets.push({ name, size: end - start, body: raw.subarray(start, end) })
    return send(res, 201, { id: rel.assets.length, name })
  }
  const body = method === 'GET' ? {} : await readBody(req)

  let x: RegExpExecArray | null
  if ((x = /^\/statuses\/([0-9a-f]+)$/.exec(rest)) && method === 'POST') {
    repo.statuses.push({ sha: x[1]!, ...(body as { state: string, context: string, description: string, target_url?: string }) })
    return send(res, 201, { id: repo.statuses.length })
  }
  if ((x = /^\/issues\/(\d+)\/comments$/.exec(rest))) {
    const n = Number(x[1])
    if (method === 'POST') return send(res, 201, addComment(f, repo, n, f.login, String(body.body ?? ''), 'Bot'))
    const since = url.searchParams.get('since')
    return send(res, 200, (repo.comments.get(n) ?? []).filter(c => !since || c.created_at >= since))
  }
  if ((x = /^\/issues\/comments\/(\d+)$/.exec(rest)) && method === 'PATCH') {
    const id = Number(x[1])
    for (const list of repo.comments.values()) {
      const c = list.find(y => y.id === id)
      if (c) {
        c.body = String(body.body ?? '')
        return send(res, 200, c)
      }
    }
    return send(res, 404, {})
  }
  if ((x = /^\/pulls\/(\d+)\/reviews$/.exec(rest)) && method === 'POST') {
    repo.reviews.push({ number: Number(x[1]), body: String(body.body ?? ''), comments: body.comments as FakeRepoState['reviews'][number]['comments'] })
    return send(res, 200, { id: repo.reviews.length })
  }
  if ((x = /^\/pulls\/(\d+)\/files$/.exec(rest))) {
    const pr = repo.prs.find(y => y.number === Number(x![1]))
    const page = Number(url.searchParams.get('page') ?? '1')
    return pr ? send(res, 200, page === 1 ? pr.files.map(filename => ({ filename, status: 'modified' })) : []) : send(res, 404, {})
  }
  if ((x = /^\/pulls\/(\d+)$/.exec(rest))) {
    const pr = repo.prs.find(y => y.number === Number(x![1]))
    return pr ? send(res, 200, prJson(pr)) : send(res, 404, {})
  }
  if (rest === '/pulls') return send(res, 200, Number(url.searchParams.get('page') ?? '1') === 1 ? repo.prs.map(prJson) : [])
  if ((x = /^\/git\/commits\/([0-9a-f]+)$/.exec(rest))) {
    const a = repo.authors[x[1]!]
    return a ? send(res, 200, { sha: x[1], author: { login: a.login }, committer: { login: a.login }, commit: { author: { email: a.email }, committer: { email: a.email } } }) : send(res, 404, {})
  }
  if ((x = /^\/collaborators\/([^/]+)\/permission$/.exec(rest))) {
    const perm = repo.permissions[decodeURIComponent(x[1]!)]
    return perm ? send(res, 200, { permission: perm }) : send(res, 404, { message: 'not a collaborator' })
  }
  if (rest === '/hooks') {
    if (method === 'POST') {
      const cfg = body.config as { url: string, secret: string }
      repo.hooks.push({ id: repo.hooks.length + 1, config: cfg, events: body.events as string[] })
      return send(res, 201, { id: repo.hooks.length })
    }
    return send(res, 200, repo.hooks.map(h => ({ id: h.id, config: { url: h.config.url } })))
  }
  return send(res, 404, {})
}

/** Démarre la fausse forge (hôte logique host) et installe le transport de test. */
export async function startFakePrForge(host: string): Promise<FakePrForge> {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const f: FakePrForge = {
    host, token: fakeToken(), login: 'scanoria-bot', repos: new Map(), requests: [],
    app: { id: 4242, slug: 'scanoria-test', pem: privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(), webhook_secret: randomBytes(24).toString('hex'), installations: [], codes: new Set() },
    close: async () => {},
  }
  const server: Server = createServer((req, res) => {
    handle(f, req, res).catch(() => send(res, 500, {}))
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  const port = typeof addr === 'object' && addr ? addr.port : 0
  setForgeTransport(async (url, init) => {
    const u = new URL(url)
    const h = u.hostname === 'api.github.com' ? 'github.com' : u.hostname
    if (h !== host) throw new TypeError('fetch failed')
    return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, init)
  })
  f.close = async () => {
    setForgeTransport()
    server.closeAllConnections()
    await new Promise(resolve => server.close(resolve))
  }
  return f
}
