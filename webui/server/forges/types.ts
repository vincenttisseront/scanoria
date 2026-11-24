// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 3 de la 0.3 : client de forge commun à Forgejo, GitHub et GitLab.

import { ForgeError } from './http'

export interface ForgeRepo {
  full_name: string
  name: string
  description: string | null
  private: boolean
  archived: boolean
  fork: boolean
  empty: boolean
  default_branch: string | null
  clone_url: string
  ssh_url: string | null
  html_url: string | null
}

export interface TreeEntry {
  path: string
  type: 'file' | 'dir'
  size: number | null
}

export interface ForgeTree {
  entries: TreeEntry[]
  /** Arbre incomplet : borne atteinte ou tronqué par la forge. */
  truncated: boolean
}

export interface ForgeClient {
  kind: 'forgejo' | 'github' | 'gitlab'
  /** Vérifie l'accès ; renvoie le compte associé au jeton (null sans jeton). */
  check: () => Promise<{ login: string | null }>
  listRepos: () => Promise<ForgeRepo[]>
  repo: (fullName: string) => Promise<ForgeRepo>
  branches: (fullName: string) => Promise<string[]>
  latestCommit: (fullName: string, branch: string) => Promise<string>
  listTree: (fullName: string, ref: string, opts?: { maxEntries?: number }) => Promise<ForgeTree>
  /** Contenu texte d'un fichier, ou null s'il n'existe pas ou dépasse maxBytes. */
  readFile: (fullName: string, ref: string, path: string, opts?: { maxBytes?: number }) => Promise<string | null>
}

export interface ForgeAccess {
  kind: 'forgejo' | 'github' | 'gitlab'
  base_url: string
  token?: string | null
}

export const MAX_REPOS = 5000
export const DEFAULT_TREE_ENTRIES = 20_000
export const DEFAULT_FILE_BYTES = 256 * 1024

const FULL_NAME_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/
/** Référence Git sûre : jamais d'option (« --upload-pack »), de « .. », de « @{ ». */
export const REF_RE = /^[A-Za-z0-9._/-]{1,255}$/
const COMMIT_RE = /^[0-9a-f]{40,64}$/

export function checkFullName(fullName: string): string {
  if (fullName.length > 300 || !FULL_NAME_RE.test(fullName) || fullName.split('/').some(s => s === '.' || s === '..')) {
    throw new ForgeError('E_FORGE_INPUT')
  }
  return fullName
}

export function isSafeRef(ref: string): boolean {
  return REF_RE.test(ref) && !/(^-|^\/|\/$|\.\.|\/\/|@\{|\.lock$|^\.|\/\.)/.test(ref)
}

export function checkRef(ref: string): string {
  if (!isSafeRef(ref)) throw new ForgeError('E_FORGE_INPUT')
  return ref
}

export function checkPath(path: string): string {
  if (!path || path.length > 1024 || path.startsWith('/') || path.includes('\\') || path.includes('\0')
    || path.split('/').some(s => s === '' || s === '.' || s === '..')) {
    throw new ForgeError('E_FORGE_INPUT')
  }
  return path
}

export function checkCommit(sha: unknown): string {
  if (typeof sha !== 'string' || !COMMIT_RE.test(sha)) throw new ForgeError('E_FORGE_RESPONSE')
  return sha
}

/** Encode chaque segment d'un chemin pour l'URL (les « / » restent). */
export function encodePath(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/')
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null)

/** Champs communs à Forgejo et GitHub (mêmes noms dans les deux API). */
export function toRepo(raw: unknown): ForgeRepo | null {
  const r = raw as Record<string, unknown> | null
  const fullName = str(r?.full_name)
  const cloneUrl = str(r?.clone_url)
  if (!r || !fullName || !FULL_NAME_RE.test(fullName) || !cloneUrl || !cloneUrl.startsWith('https://')) return null
  return {
    full_name: fullName,
    name: str(r.name) ?? fullName.split('/').pop()!,
    description: str(r.description)?.slice(0, 500) || null,
    private: r.private === true,
    archived: r.archived === true,
    fork: r.fork === true,
    empty: r.empty === true,
    default_branch: str(r.default_branch) && isSafeRef(r.default_branch as string) ? (r.default_branch as string) : null,
    clone_url: cloneUrl,
    ssh_url: str(r.ssh_url),
    html_url: str(r.html_url),
  }
}

/**
 * URL de clonage HTTPS d'un dépôt, reconstruite depuis l'URL de la forge et
 * jamais reprise de la réponse de l'API : le jeton de la forge ne part ainsi
 * que vers la forge elle-même.
 */
export function cloneUrlFor(baseUrl: string, fullName: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/${checkFullName(fullName)}.git`
}
