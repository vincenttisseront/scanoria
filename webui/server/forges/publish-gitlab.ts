// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 pour GitLab (API v4) : statuts de commit, note de synthèse de la
// merge request, discussions ligne à ligne, fichiers modifiés, auteurs (adresse
// seulement : GitLab ne relie pas un commit à un compte), MR ouvertes et notes
// (mode tiré), webhook de projet.

import { ForgeError, forgeGetJson, forgeSendJson } from './http'
import { gitlabApiBase, gitlabProjectId, gitlabRequest } from './gitlab'
import { checkCommit, type ForgeAccess } from './types'
import {
  checkNumber, emailOf, loginOf, uniqueAuthors,
  type ForgeComment, type ForgePublisherImpl, type PullRequestRef,
} from './pr-types'

const PAGE = 100
const SHA_RE = /^[0-9a-f]{40,64}$/

function toMergeRequest(raw: unknown): PullRequestRef | null {
  const r = raw as { iid?: unknown, sha?: unknown, source_branch?: unknown, target_branch?: unknown, diff_refs?: { base_sha?: unknown }, author?: { username?: unknown }, draft?: unknown } | null
  const head = typeof r?.sha === 'string' ? r.sha : null
  const base = typeof r?.diff_refs?.base_sha === 'string' ? r.diff_refs.base_sha : null
  if (!r || typeof r.iid !== 'number' || !head || !SHA_RE.test(head) || !base || !SHA_RE.test(base)
    || typeof r.source_branch !== 'string' || typeof r.target_branch !== 'string') return null
  return {
    number: r.iid,
    head_sha: head,
    head_ref: r.source_branch.slice(0, 255),
    base_sha: base,
    base_ref: r.target_branch.slice(0, 255),
    author: loginOf(r.author?.username),
    draft: r.draft === true,
  }
}

export function gitlabPublisher(access: ForgeAccess): ForgePublisherImpl {
  const api = gitlabApiBase(access.base_url)
  const req = gitlabRequest(access)
  const proj = (r: string) => `${api}/projects/${gitlabProjectId(r)}`
  const mr = (r: string, n: number) => `${proj(r)}/merge_requests/${checkNumber(n)}`

  async function pages<T>(url: (page: number) => string, max: number): Promise<T[]> {
    const out: T[] = []
    for (let page = 1; out.length < max && page <= 100; page++) {
      const { data } = await forgeGetJson(url(page), req)
      const items = Array.isArray(data) ? data as T[] : []
      out.push(...items)
      if (items.length < PAGE) break
    }
    return out.slice(0, max)
  }

  return {
    kind: 'gitlab',

    async setCommitStatus(repo, s) {
      const state = s.state === 'failure' || s.state === 'error' ? 'failed' : s.state
      await forgeSendJson(`${proj(repo)}/statuses/${checkCommit(s.sha)}`, req, {
        method: 'POST',
        json: { state, name: s.context, description: s.description, ...(s.target_url ? { target_url: s.target_url } : {}) },
      })
    },

    async createComment(repo, number, body) {
      const { data } = await forgeSendJson<{ id?: unknown }>(`${mr(repo, number)}/notes`, req, { method: 'POST', json: { body } })
      if (typeof data?.id !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
      return String(data.id)
    },

    async updateComment(repo, number, commentId, body) {
      if (!/^\d{1,19}$/.test(commentId)) throw new ForgeError('E_FORGE_INPUT')
      await forgeSendJson(`${mr(repo, number)}/notes/${commentId}`, req, { method: 'PUT', json: { body } })
    },

    async publishAnnotations(repo, pr, annotations) {
      let count = 0
      let first: string | null = null
      for (const a of annotations) {
        try {
          const { data } = await forgeSendJson<{ id?: unknown }>(`${mr(repo, pr.number)}/discussions`, req, {
            method: 'POST',
            json: {
              body: `**${a.title}**\n\n${a.message}`,
              position: { position_type: 'text', base_sha: pr.base_sha, start_sha: pr.base_sha, head_sha: pr.head_sha, new_path: a.path, new_line: a.line },
            },
          })
          first ??= typeof data?.id === 'string' ? data.id.slice(0, 128) : null
          count++
        }
        catch (err) {
          // Ligne hors du diff (400) : l'annotation reste dans la console seulement.
          if (!(err instanceof ForgeError) || err.code !== 'E_FORGE_RESPONSE' || err.status !== 400) throw err
        }
      }
      return { kind: 'pr-review', id: first, count }
    },

    async changedFiles(repo, number, max) {
      const raw = await pages<{ new_path?: unknown, deleted_file?: unknown }>(p => `${mr(repo, number)}/diffs?per_page=${PAGE}&page=${p}`, max + 1)
      const files = raw.filter(f => f?.deleted_file !== true).map(f => f?.new_path).filter((f): f is string => typeof f === 'string')
      return { files: files.slice(0, max), truncated: raw.length > max }
    },

    async commitAuthors(repo, sha) {
      const { data } = await forgeGetJson<{ author_email?: unknown, committer_email?: unknown }>(`${proj(repo)}/repository/commits/${checkCommit(sha)}`, req)
      return uniqueAuthors([emailOf(data?.author_email), emailOf(data?.committer_email)])
    },

    async pullRequest(repo, number) {
      const { data } = await forgeGetJson(mr(repo, number), req)
      const pr = toMergeRequest(data)
      if (!pr) throw new ForgeError('E_FORGE_RESPONSE')
      return pr
    },

    async openPullRequests(repo, max) {
      const raw = await pages<unknown>(p => `${proj(repo)}/merge_requests?state=opened&per_page=${PAGE}&page=${p}`, max)
      // La liste ne porte pas diff_refs : chaque MR est relue (borné par max).
      const out: PullRequestRef[] = []
      for (const r of raw) {
        const iid = (r as { iid?: unknown } | null)?.iid
        if (typeof iid !== 'number') continue
        const one = await forgeGetJson(mr(repo, iid), req).then(x => toMergeRequest(x.data)).catch(() => null)
        if (one) out.push(one)
      }
      return out
    },

    async comments(repo, number, since) {
      const raw = await pages<{ id?: unknown, body?: unknown, created_at?: unknown, system?: unknown, author?: { username?: unknown, bot?: unknown } }>(
        p => `${mr(repo, number)}/notes?sort=asc&order_by=created_at&per_page=${PAGE}&page=${p}`, 1000)
      return raw.flatMap((c): ForgeComment[] => typeof c?.id === 'number' && typeof c.body === 'string' && c.system !== true
        && (!since || String(c.created_at ?? '') > since)
        ? [{ id: String(c.id), author: loginOf(c.author?.username), author_is_bot: c.author?.bot === true, body: c.body, created_at: String(c.created_at ?? '') }]
        : [])
    },

    async ensureWebhook(repo, url, secret) {
      const hooks = await pages<{ url?: unknown }>(p => `${proj(repo)}/hooks?per_page=${PAGE}&page=${p}`, 200)
      if (hooks.some(h => h?.url === url)) return 'exists'
      await forgeSendJson(`${proj(repo)}/hooks`, req, {
        method: 'POST',
        json: { url, token: secret, push_events: true, merge_requests_events: true, note_events: true, enable_ssl_verification: true },
      })
      return 'created'
    },
  }
}
