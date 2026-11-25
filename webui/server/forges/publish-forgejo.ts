// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 pour Forgejo (API v1, compatible Gitea) : statuts de commit,
// commentaire de synthèse, revue ligne à ligne, fichiers modifiés, auteurs,
// PR ouvertes et commentaires (mode tiré), webhook de dépôt.

import { ForgeError, forgeGetJson, forgeSendJson, type ForgeRequest } from './http'
import { checkCommit, checkFullName, encodePath, type ForgeAccess } from './types'
import {
  checkNumber, emailOf, loginOf, toPullRequest, uniqueAuthors,
  type ForgeComment, type ForgePublisherImpl, type PullRequestRef,
} from './pr-types'

const PAGE = 50
const EVENTS = ['push', 'pull_request', 'pull_request_sync', 'issue_comment']

export function forgejoPublisher(access: ForgeAccess): ForgePublisherImpl {
  const api = `${access.base_url}/api/v1`
  const req: ForgeRequest = { token: access.token, authScheme: 'token' }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`

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
    kind: 'forgejo',

    async setCommitStatus(repo, s) {
      await forgeSendJson(`${repoUrl(repo)}/statuses/${checkCommit(s.sha)}`, req, {
        method: 'POST',
        json: { state: s.state, context: s.context, description: s.description, ...(s.target_url ? { target_url: s.target_url } : {}) },
      })
    },

    async createComment(repo, number, body) {
      const { data } = await forgeSendJson<{ id?: unknown }>(`${repoUrl(repo)}/issues/${checkNumber(number)}/comments`, req, { method: 'POST', json: { body } })
      if (typeof data?.id !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
      return String(data.id)
    },

    async updateComment(repo, _number, commentId, body) {
      if (!/^\d{1,19}$/.test(commentId)) throw new ForgeError('E_FORGE_INPUT')
      await forgeSendJson(`${repoUrl(repo)}/issues/comments/${commentId}`, req, { method: 'PATCH', json: { body } })
    },

    async publishAnnotations(repo, pr, annotations, summary) {
      if (!annotations.length) return { kind: 'pr-review', id: null, count: 0 }
      const { data } = await forgeSendJson<{ id?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(pr.number)}/reviews`, req, {
        method: 'POST',
        json: {
          commit_id: checkCommit(pr.head_sha),
          event: 'COMMENT',
          body: summary,
          comments: annotations.map(a => ({ path: a.path, new_position: a.line, body: `**${a.title}**\n\n${a.message}` })),
        },
      })
      return { kind: 'pr-review', id: typeof data?.id === 'number' ? String(data.id) : null, count: annotations.length }
    },

    async changedFiles(repo, number, max) {
      const raw = await pages<{ filename?: unknown, status?: unknown }>(p => `${repoUrl(repo)}/pulls/${checkNumber(number)}/files?limit=${PAGE}&page=${p}`, max + 1)
      const files = raw.filter(f => f?.status !== 'deleted').map(f => f?.filename).filter((f): f is string => typeof f === 'string')
      return { files: files.slice(0, max), truncated: raw.length > max }
    },

    async commitAuthors(repo, sha) {
      const { data } = await forgeGetJson<{ author?: { login?: unknown }, committer?: { login?: unknown }, commit?: { author?: { email?: unknown }, committer?: { email?: unknown } } }>(
        `${repoUrl(repo)}/git/commits/${checkCommit(sha)}?stat=false&verification=false&files=false`, req)
      return uniqueAuthors([loginOf(data?.author?.login), emailOf(data?.commit?.author?.email), loginOf(data?.committer?.login), emailOf(data?.commit?.committer?.email)])
    },

    async pullRequest(repo, number) {
      const { data } = await forgeGetJson(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      const pr = toPullRequest(data)
      if (!pr) throw new ForgeError('E_FORGE_RESPONSE')
      return pr
    },

    async openPullRequests(repo, max) {
      const raw = await pages<unknown>(p => `${repoUrl(repo)}/pulls?state=open&limit=${PAGE}&page=${p}`, max)
      return raw.map(toPullRequest).filter((p): p is PullRequestRef => !!p)
    },

    async comments(repo, number, since) {
      const q = since ? `&since=${encodeURIComponent(since)}` : ''
      const raw = await pages<{ id?: unknown, body?: unknown, created_at?: unknown, user?: { login?: unknown, type?: unknown } }>(
        p => `${repoUrl(repo)}/issues/${checkNumber(number)}/comments?limit=${PAGE}&page=${p}${q}`, 500)
      return raw.flatMap((c): ForgeComment[] => typeof c?.id === 'number' && typeof c.body === 'string'
        ? [{ id: String(c.id), author: loginOf(c.user?.login), author_is_bot: c.user?.type === 'Bot', body: c.body, created_at: String(c.created_at ?? '') }]
        : [])
    },

    async ensureWebhook(repo, url, secret) {
      const hooks = await pages<{ config?: { url?: unknown } }>(p => `${repoUrl(repo)}/hooks?limit=${PAGE}&page=${p}`, 200)
      if (hooks.some(h => h?.config?.url === url)) return 'exists'
      await forgeSendJson(`${repoUrl(repo)}/hooks`, req, {
        method: 'POST',
        json: { type: 'gitea', active: true, events: EVENTS, branch_filter: '*', config: { url, content_type: 'json', secret } },
      })
      return 'created'
    },
  }
}
