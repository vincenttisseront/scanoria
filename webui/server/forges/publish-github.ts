// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 pour GitHub (REST v3, github.com ou GitHub Enterprise Server).
// Annotations : check run (application GitHub, J1) ; avec un simple jeton, qui
// ne peut pas créer de check run, revue de PR en commentaires de lignes.

import { ForgeError, forgeGetJson, forgeSendJson, type ForgeRequest } from './http'
import { githubApiBase } from './github'
import { checkCommit, checkFullName, encodePath, type ForgeAccess } from './types'
import {
  checkNumber, emailOf, loginOf, toPullRequest, uniqueAuthors,
  type Annotation, type ForgeComment, type ForgePublisherImpl, type PullRequestRef,
} from './pr-types'

const PAGE = 100
/** GitHub accepte 50 annotations par appel. */
const CHECK_BATCH = 50

export function githubPublisher(access: ForgeAccess): ForgePublisherImpl {
  const api = githubApiBase(access.base_url)
  const req: ForgeRequest = {
    token: access.token,
    authScheme: 'Bearer',
    accept: 'application/vnd.github+json',
    headers: { 'x-github-api-version': '2022-11-28' },
  }
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

  async function review(repo: string, pr: PullRequestRef, annotations: Annotation[], summary: string) {
    const { data } = await forgeSendJson<{ id?: unknown }>(`${repoUrl(repo)}/pulls/${checkNumber(pr.number)}/reviews`, req, {
      method: 'POST',
      json: {
        commit_id: checkCommit(pr.head_sha),
        event: 'COMMENT',
        body: summary,
        comments: annotations.map(a => ({ path: a.path, line: a.line, side: 'RIGHT', body: `**${a.title}**\n\n${a.message}` })),
      },
    })
    return { kind: 'pr-review' as const, id: typeof data?.id === 'number' ? String(data.id) : null, count: annotations.length }
  }

  return {
    kind: 'github',

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

    async publishAnnotations(repo, pr, annotations, summary, conclusion) {
      const level = (l: Annotation['level']) => (l === 'failure' ? 'failure' : l === 'warning' ? 'warning' : 'notice')
      const out = annotations.map(a => ({ path: a.path, start_line: a.line, end_line: a.line, annotation_level: level(a.level), title: a.title, message: a.message }))
      const checkConclusion = conclusion === 'success' ? 'success' : conclusion === 'pending' ? 'neutral' : 'failure'
      try {
        const first = await forgeSendJson<{ id?: unknown }>(`${repoUrl(repo)}/check-runs`, req, {
          method: 'POST',
          json: {
            name: 'scanoria', head_sha: checkCommit(pr.head_sha), status: 'completed', conclusion: checkConclusion,
            output: { title: 'Scanoria', summary, annotations: out.slice(0, CHECK_BATCH) },
          },
        })
        const id = typeof first.data?.id === 'number' ? String(first.data.id) : null
        for (let i = CHECK_BATCH; id && i < out.length; i += CHECK_BATCH) {
          await forgeSendJson(`${repoUrl(repo)}/check-runs/${id}`, req, {
            method: 'PATCH', json: { output: { title: 'Scanoria', summary, annotations: out.slice(i, i + CHECK_BATCH) } },
          })
        }
        return { kind: 'check-run', id, count: out.length }
      }
      catch (err) {
        // Jeton sans droit sur les check runs (pas une application) : revue de PR.
        if (!(err instanceof ForgeError) || err.code !== 'E_FORGE_AUTH' || !annotations.length) throw err
        return review(repo, pr, annotations, summary)
      }
    },

    async changedFiles(repo, number, max) {
      const raw = await pages<{ filename?: unknown, status?: unknown }>(p => `${repoUrl(repo)}/pulls/${checkNumber(number)}/files?per_page=${PAGE}&page=${p}`, max + 1)
      const files = raw.filter(f => f?.status !== 'removed').map(f => f?.filename).filter((f): f is string => typeof f === 'string')
      return { files: files.slice(0, max), truncated: raw.length > max }
    },

    async commitAuthors(repo, sha) {
      const { data } = await forgeGetJson<{ author?: { login?: unknown }, committer?: { login?: unknown }, commit?: { author?: { email?: unknown }, committer?: { email?: unknown } } }>(
        `${repoUrl(repo)}/commits/${checkCommit(sha)}`, { ...req, maxBytes: 2 * 1024 * 1024 })
      return uniqueAuthors([loginOf(data?.author?.login), emailOf(data?.commit?.author?.email), loginOf(data?.committer?.login), emailOf(data?.commit?.committer?.email)])
    },

    async pullRequest(repo, number) {
      const { data } = await forgeGetJson(`${repoUrl(repo)}/pulls/${checkNumber(number)}`, req)
      const pr = toPullRequest(data)
      if (!pr) throw new ForgeError('E_FORGE_RESPONSE')
      return pr
    },

    async openPullRequests(repo, max) {
      const raw = await pages<unknown>(p => `${repoUrl(repo)}/pulls?state=open&per_page=${PAGE}&page=${p}`, max)
      return raw.map(toPullRequest).filter((p): p is PullRequestRef => !!p)
    },

    async comments(repo, number, since) {
      const q = since ? `&since=${encodeURIComponent(since)}` : ''
      const raw = await pages<{ id?: unknown, body?: unknown, created_at?: unknown, user?: { login?: unknown, type?: unknown } }>(
        p => `${repoUrl(repo)}/issues/${checkNumber(number)}/comments?per_page=${PAGE}&page=${p}${q}`, 500)
      return raw.flatMap((c): ForgeComment[] => typeof c?.id === 'number' && typeof c.body === 'string'
        ? [{ id: String(c.id), author: loginOf(c.user?.login), author_is_bot: c.user?.type === 'Bot', body: c.body, created_at: String(c.created_at ?? '') }]
        : [])
    },

    // Application GitHub : un seul webhook, déclaré dans le manifeste (J1).
    async ensureWebhook() {
      return 'app'
    },
  }
}
