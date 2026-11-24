// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// URL Git libre d'un projet : HTTPS sans identifiants, ou SSH (ssh://user@hôte
// ou user@hôte:chemin). Tout le reste est refusé : file://, ext::, git://,
// http://, option déguisée (« -oProxyCommand »), bouclage, lien local.

import { ForgeError, normalizeBaseUrl } from '../forges/http'

export interface GitUrl {
  kind: 'https' | 'ssh'
  url: string
  host: string
  port: number
  path: string
}

const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/
const USER_RE = /^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}$/
const PATH_RE = /^[A-Za-z0-9._~/-]+$/

export class GitUrlError extends Error {
  constructor() {
    super('E_GIT_URL')
    this.name = 'GitUrlError'
  }
}

function checkHost(host: string): void {
  if (!HOST_RE.test(host)) throw new GitUrlError()
  // Mêmes refus que pour une forge (bouclage, lien local).
  try {
    normalizeBaseUrl(`https://${host}`)
  }
  catch (err) {
    if (err instanceof ForgeError) throw new GitUrlError()
    throw err
  }
}

function checkRepoPath(path: string, host: string): string {
  const p = path.replace(/^\/+/, '')
  if (!p || p.length > 512 || !PATH_RE.test(p) || p.startsWith('-') || p.split('/').some(s => s === '..' || s === '.')) throw new GitUrlError()
  // github.com : « propriétaire/dépôt » seulement (une adresse de page comme
  // …/tree/v1.0 n'est pas un dépôt).
  if (host.toLowerCase() === 'github.com' && !/^[^/]+\/[^/]+$/.test(p.replace(/\/+$/, ''))) throw new GitUrlError()
  return p
}

export function parseGitUrl(raw: string): GitUrl {
  const s = raw.trim()
  if (!s || s.length > 1024 || /[\s\0]/.test(s) || s.startsWith('-')) throw new GitUrlError()
  if (s.split(/[/:]/).some(seg => seg === '..' || seg === '.')) throw new GitUrlError()
  if (s.startsWith('https://')) {
    let u: URL
    try {
      u = new URL(s)
    }
    catch {
      throw new GitUrlError()
    }
    if (u.username || u.password || u.search || u.hash || s.includes('@')) throw new GitUrlError()
    checkHost(u.hostname)
    let decoded: string
    try {
      decoded = decodeURIComponent(u.pathname)
    }
    catch {
      throw new GitUrlError()
    }
    const path = checkRepoPath(decoded, u.hostname)
    const port = u.port ? Number(u.port) : 443
    return { kind: 'https', url: `https://${u.host}/${path}`, host: u.hostname.toLowerCase(), port, path }
  }
  if (s.startsWith('ssh://')) {
    const m = /^ssh:\/\/([^@/]+)@([^/:]+)(?::([0-9]{1,5}))?\/(.+)$/.exec(s)
    if (!m) throw new GitUrlError()
    const [, user, host, port, path] = m
    if (!USER_RE.test(user!)) throw new GitUrlError()
    checkHost(host!)
    const p = Number(port ?? 22)
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new GitUrlError()
    const repoPath = checkRepoPath(path!, host!)
    return { kind: 'ssh', url: `ssh://${user}@${host!.toLowerCase()}${port ? `:${p}` : ''}/${repoPath}`, host: host!.toLowerCase(), port: p, path: repoPath }
  }
  // Forme scp : user@hôte:chemin (jamais de « :: », qui désigne ext:: ou un transport).
  const m = /^([^@:/]+)@([^:/]+):(?!:)(.+)$/.exec(s)
  if (!m || s.includes('::')) throw new GitUrlError()
  const [, user, host, path] = m
  if (!USER_RE.test(user!)) throw new GitUrlError()
  checkHost(host!)
  const repoPath = checkRepoPath(path!, host!)
  return { kind: 'ssh', url: `${user}@${host!.toLowerCase()}:${repoPath}`, host: host!.toLowerCase(), port: 22, path: repoPath }
}

/** « propriétaire/dépôt » déduit du chemin (sans « .git »), ou null. */
export function fullNameFromPath(path: string): string | null {
  const p = path.replace(/\.git$/, '')
  return /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/.test(p) ? p : null
}
