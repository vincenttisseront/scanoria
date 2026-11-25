// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Types et lectures communes du contrat 30 (client de forge pour les PR).

import { ForgeError } from './http'

export const MAX_ANNOTATIONS = 30
export const MAX_CHANGED_FILES = 3000
export const SHA_RE = /^[0-9a-f]{40,64}$/

export interface PullRequestRef {
  number: number
  head_sha: string
  head_ref: string
  base_sha: string
  base_ref: string
  /** Identifiant de l'auteur dans la forge (login), null s'il est inconnu. */
  author: string | null
  draft: boolean
}

export interface ForgeComment {
  id: string
  author: string | null
  /** Compte de robot ou d'application (jamais traité comme une personne). */
  author_is_bot: boolean
  body: string
  created_at: string
}

export type CommitState = 'pending' | 'success' | 'failure' | 'error'

export interface CommitStatusInput {
  sha: string
  /** « scanoria/<profil> » ; caractères sûrs seulement. */
  context: string
  state: CommitState
  /** Texte court (140 caractères au plus, une ligne). */
  description: string
  target_url: string | null
}

export interface Annotation {
  path: string
  line: number
  level: 'failure' | 'warning' | 'notice'
  title: string
  message: string
}

export interface AnnotationResult {
  kind: 'check-run' | 'pr-review'
  id: string | null
  count: number
}

/** Ce que chaque forge implémente ; les textes y arrivent déjà neutralisés. */
/** Droit sur un dépôt, ramené à trois niveaux communs aux forges. */
export type RepoPermission = 'admin' | 'write' | 'read' | 'none'

const LOGIN_SAFE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/

/** Identifiant de compte sûr dans une URL de forge. */
export function checkLogin(login: string): string {
  if (!LOGIN_SAFE_RE.test(login)) throw new ForgeError('E_FORGE_INPUT')
  return login
}

/** Droit Forgejo ou GitHub (« maintain », « triage »… compris). */
export function toPermission(raw: unknown): RepoPermission {
  const p = typeof raw === 'string' ? raw.toLowerCase() : ''
  if (p === 'admin' || p === 'owner') return 'admin'
  if (p === 'write' || p === 'maintain' || p === 'push') return 'write'
  if (p === 'read' || p === 'triage' || p === 'pull') return 'read'
  return 'none'
}

export interface ForgePublisherImpl {
  kind: 'forgejo' | 'github' | 'gitlab'
  setCommitStatus: (repo: string, s: CommitStatusInput) => Promise<void>
  createComment: (repo: string, number: number, body: string) => Promise<string>
  updateComment: (repo: string, number: number, commentId: string, body: string) => Promise<void>
  publishAnnotations: (repo: string, pr: PullRequestRef, annotations: Annotation[], summary: string, conclusion: CommitState) => Promise<AnnotationResult>
  changedFiles: (repo: string, number: number, max: number) => Promise<{ files: string[], truncated: boolean }>
  commitAuthors: (repo: string, sha: string) => Promise<string[]>
  pullRequest: (repo: string, number: number) => Promise<PullRequestRef>
  openPullRequests: (repo: string, max: number) => Promise<PullRequestRef[]>
  comments: (repo: string, number: number, since: string | null) => Promise<ForgeComment[]>
  /** Droit d'un compte sur le dépôt, lu dans la forge ('none' s'il n'y est pas). */
  permission: (repo: string, login: string) => Promise<RepoPermission>
  /** Crée le webhook de l'appliance s'il n'existe pas (Forgejo, GitLab ; sans effet pour une application GitHub). */
  ensureWebhook: (repo: string, url: string, secret: string) => Promise<'created' | 'exists' | 'app'>
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

/** Numéro de PR sûr (entier positif borné). */
export function checkNumber(n: unknown): number {
  if (typeof n !== 'number' || !Number.isInteger(n) || n < 1 || n > 1e9) throw new ForgeError('E_FORGE_INPUT')
  return n
}

/** PR normalisée depuis les champs Forgejo et GitHub (mêmes noms). */
export function toPullRequest(raw: unknown): PullRequestRef | null {
  const r = raw as { number?: unknown, head?: { sha?: unknown, ref?: unknown }, base?: { sha?: unknown, ref?: unknown }, user?: { login?: unknown }, draft?: unknown } | null
  const head = str(r?.head?.sha)
  const base = str(r?.base?.sha)
  const headRef = str(r?.head?.ref)
  const baseRef = str(r?.base?.ref)
  if (!r || typeof r.number !== 'number' || !head || !SHA_RE.test(head) || !base || !SHA_RE.test(base) || !headRef || !baseRef) return null
  return {
    number: r.number,
    head_sha: head,
    head_ref: headRef.slice(0, 255),
    base_sha: base,
    base_ref: baseRef.slice(0, 255),
    author: loginOf(r.user?.login),
    draft: r.draft === true,
  }
}

/** Identifiant de forge sûr, ou null. */
export function loginOf(v: unknown): string | null {
  return typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._[\]-]{0,99}$/.test(v) ? v : null
}

/** Adresse électronique plausible, en minuscules, ou null. */
export function emailOf(v: unknown): string | null {
  return typeof v === 'string' && v.length <= 254 && /^[^\s@<>]+@[^\s@<>]+$/.test(v) ? v.toLowerCase() : null
}

export function uniqueAuthors(list: (string | null)[]): string[] {
  return [...new Set(list.filter((x): x is string => !!x))].slice(0, 20)
}
