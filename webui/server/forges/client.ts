// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 30 (0.7) : client de forge commun pour publier dans les PR et lire
// ce qu'il faut pour les analyser. Forgejo d'abord (D4), puis GitHub et
// GitLab. Les autres chantiers publient seulement par ce client.
// - Tout texte publié passe par sanitizeForForge (aucune exception : les
//   implémentations ne reçoivent que du texte déjà neutralisé) ;
// - délais et tailles bornés (http.ts), réessais avec recul sur une erreur
//   passagère (withForgeRetry) ;
// - aucune fusion, aucune fermeture, aucun réglage de dépôt : seulement des
//   statuts, des commentaires, des revues ou check runs et des webhooks.

import { ForgeError, normalizeBaseUrl, withForgeRetry } from './http'
import { forgejoPublisher } from './publish-forgejo'
import { githubPublisher } from './publish-github'
import { gitlabPublisher } from './publish-gitlab'
import { sanitizeForForge } from './sanitize'
import type { ForgeAccess } from './types'

import { MAX_ANNOTATIONS, MAX_CHANGED_FILES, SHA_RE, type ForgePublisherImpl } from './pr-types'

export { sanitizeForForge, escapeInline, codeBlock } from './sanitize'
export * from './pr-types'

export type ForgePublisher = Omit<ForgePublisherImpl, 'createComment' | 'updateComment'> & {
  /** Commentaire de synthèse mis à jour en place (un seul par PR) ; rend son identifiant. */
  upsertComment: (repo: string, number: number, markdown: string, commentId: string | null) => Promise<string>
  /** Réponse ponctuelle (commande /scanoria). */
  replyComment: (repo: string, number: number, markdown: string) => Promise<string>
}

export interface PublisherOptions {
  /** Origine de la console : seuls liens libres permis dans les textes publiés. */
  consoleUrl: string | null
}

const CONTEXT_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/

/** Description d'un statut : une ligne de texte brut, sans contrôle, bornée. */
export function statusDescription(text: string): string {
  // eslint-disable-next-line no-control-regex
  const s = text.replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim()
  return s.length > 140 ? `${s.slice(0, 139)}…` : s
}

function implFor(access: ForgeAccess): ForgePublisherImpl {
  const a = { ...access, base_url: normalizeBaseUrl(access.base_url) }
  switch (access.kind) {
    case 'forgejo': return forgejoPublisher(a)
    case 'github': return githubPublisher(a)
    case 'gitlab': return gitlabPublisher(a)
    default: throw new ForgeError('E_FORGE_UNSUPPORTED')
  }
}

/** Contrat 30 : client de publication d'une forge. */
export function forgePublisher(access: ForgeAccess, opts: PublisherOptions): ForgePublisher {
  const impl = implFor(access)
  const clean = (md: string) => sanitizeForForge(md, { consoleUrl: opts.consoleUrl })
  return {
    kind: impl.kind,
    setCommitStatus: (repo, s) => {
      if (!SHA_RE.test(s.sha) || !CONTEXT_RE.test(s.context)) throw new ForgeError('E_FORGE_INPUT')
      const target = s.target_url && opts.consoleUrl && s.target_url.startsWith(`${new URL(opts.consoleUrl).origin}/`) ? s.target_url : null
      return withForgeRetry(() => impl.setCommitStatus(repo, { ...s, description: statusDescription(s.description), target_url: target }))
    },
    upsertComment: async (repo, number, markdown, commentId) => {
      const body = clean(markdown)
      if (commentId) {
        try {
          await withForgeRetry(() => impl.updateComment(repo, number, commentId, body))
          return commentId
        }
        catch (err) {
          // Commentaire supprimé à la main : un nouveau le remplace.
          if (!(err instanceof ForgeError) || err.code !== 'E_FORGE_NOT_FOUND') throw err
        }
      }
      return withForgeRetry(() => impl.createComment(repo, number, body))
    },
    replyComment: (repo, number, markdown) => withForgeRetry(() => impl.createComment(repo, number, clean(markdown))),
    publishAnnotations: (repo, pr, annotations, summary, conclusion) => withForgeRetry(() => impl.publishAnnotations(repo, pr,
      annotations.slice(0, MAX_ANNOTATIONS).map(x => ({ ...x, title: statusDescription(x.title), message: clean(x.message) })),
      clean(summary), conclusion)),
    changedFiles: (repo, number, max) => withForgeRetry(() => impl.changedFiles(repo, number, Math.min(max, MAX_CHANGED_FILES))),
    commitAuthors: (repo, sha) => {
      if (!SHA_RE.test(sha)) throw new ForgeError('E_FORGE_INPUT')
      return withForgeRetry(() => impl.commitAuthors(repo, sha))
    },
    pullRequest: (repo, number) => withForgeRetry(() => impl.pullRequest(repo, number)),
    openPullRequests: (repo, max) => withForgeRetry(() => impl.openPullRequests(repo, max)),
    comments: (repo, number, since) => withForgeRetry(() => impl.comments(repo, number, since)),
    ensureWebhook: (repo, url, secret) => withForgeRetry(() => impl.ensureWebhook(repo, url, secret)),
  }
}
