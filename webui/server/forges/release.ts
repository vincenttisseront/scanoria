// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.8 (chantier A, contrat 42) : ajouts au client de forge pour la gate de
// release (CLAUDE.md § 7). Requêtes sortantes seulement :
// - tags et releases (pré-versions comprises) d'un dépôt, pour le mode tiré ;
// - fichiers joints à une release existante (rapport signé, SARIF fusionné,
//   SBOM CycloneDX, § 7.3), quand la forge le permet et que l'accès en a le
//   droit ; sinon le droit manquant est rendu, jamais contourné.
// Aucune release n'est créée, modifiée ni supprimée par l'appliance.

import { randomBytes } from 'node:crypto'
import { ForgeError, forgeGetJson, forgeSendJson, withForgeRetry, type ForgeRequest } from './http'
import { githubApiBase } from './github'
import { gitlabApiBase, gitlabProjectId, gitlabRequest } from './gitlab'
import { checkFullName, encodePath, type ForgeAccess } from './types'

const PAGE = 50
export const MAX_TAGS = 500
const SHA_RE = /^[0-9a-f]{40,64}$/
/** Nom de tag sûr dans une URL et dans un motif (réf. Git restreinte). */
export const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9._+/-]{0,254}$/
const ASSET_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

export interface ForgeTag {
  name: string
  commit_sha: string
  /** Une release de la forge existe pour ce tag (pré-version ou non). */
  release: boolean
  prerelease: boolean
}

export type AssetOutcome = 'uploaded' | 'exists' | 'no-release' | 'unsupported'

export interface ReleaseForge {
  /** Tags du dépôt (les plus récents d'abord selon la forge), avec l'état de leur release. */
  tags: (repo: string, max?: number) => Promise<ForgeTag[]>
  /** Joint un fichier à la release du tag ; jamais de création de release. */
  uploadAsset: (repo: string, tag: string, name: string, data: Buffer, contentType: string) => Promise<AssetOutcome>
}

export function isSafeTag(tag: string): boolean {
  return TAG_RE.test(tag) && !tag.includes('..') && !tag.endsWith('/') && !tag.endsWith('.lock') && !tag.includes('//')
}

/**
 * Droit manquant pour joindre des fichiers à une release, ou null.
 * GitHub (application J1) : contents:write ; jeton de service Forgejo :
 * write:repository (déjà demandé) ; GitLab : api (déjà demandé).
 */
export function missingAssetPermission(kind: ForgeAccess['kind'], appPermissions: Record<string, unknown> | null | undefined): string | null {
  if (kind !== 'github' || !appPermissions) return null
  return appPermissions.contents === 'write' ? null : 'contents:write'
}

interface RawRelease { tag_name?: unknown, prerelease?: unknown, draft?: unknown, upcoming_release?: unknown }

function str(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

function mergeReleases(tags: { name: string, commit_sha: string }[], releases: RawRelease[]): ForgeTag[] {
  const rel = new Map<string, boolean>()
  for (const r of releases) {
    const t = str(r?.tag_name)
    if (t && r.draft !== true) rel.set(t, r.prerelease === true || r.upcoming_release === true)
  }
  return tags.map(t => ({ ...t, release: rel.has(t.name), prerelease: rel.get(t.name) ?? false }))
}

function toTag(name: unknown, sha: unknown): { name: string, commit_sha: string } | null {
  const n = str(name)
  const s = str(sha)
  return n && s && isSafeTag(n) && SHA_RE.test(s) ? { name: n, commit_sha: s } : null
}

/** Corps multipart/form-data d'un seul fichier (Forgejo, GitLab). */
export function multipartFile(field: string, name: string, data: Buffer, contentType: string): { body: Buffer, contentType: string } {
  const boundary = `scanoria-${randomBytes(12).toString('hex')}`
  const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="${name}"\r\nContent-Type: ${contentType}\r\n\r\n`, 'utf8')
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8')
  return { body: Buffer.concat([head, data, tail]), contentType: `multipart/form-data; boundary=${boundary}` }
}

async function pages<T>(req: ForgeRequest, url: (page: number) => string, max: number, perPage = PAGE): Promise<T[]> {
  const out: T[] = []
  for (let page = 1; out.length < max && page <= 20; page++) {
    const { data } = await forgeGetJson(url(page), req)
    const items = Array.isArray(data) ? data as T[] : []
    out.push(...items)
    if (items.length < perPage) break
  }
  return out.slice(0, max)
}

/** Fichier refusé parce qu'il existe déjà (même nom) : 409 ou 422 selon la forge. */
function exists(err: unknown): boolean {
  return err instanceof ForgeError && err.code === 'E_FORGE_RESPONSE' && (err.status === 409 || err.status === 422)
}

async function sendOrExists(fn: () => Promise<unknown>): Promise<AssetOutcome> {
  try {
    await withForgeRetry(fn)
    return 'uploaded'
  }
  catch (err) {
    if (exists(err)) return 'exists'
    throw err
  }
}

function forgejo(access: ForgeAccess): ReleaseForge {
  const api = `${access.base_url}/api/v1`
  const req: ForgeRequest = { token: access.token, authScheme: 'token' }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  return {
    async tags(repo, max = MAX_TAGS) {
      const raw = await pages<{ name?: unknown, commit?: { sha?: unknown } }>(req, p => `${repoUrl(repo)}/tags?limit=${PAGE}&page=${p}`, max)
      const rel = await pages<RawRelease>(req, p => `${repoUrl(repo)}/releases?limit=${PAGE}&page=${p}`, max)
      return mergeReleases(raw.map(t => toTag(t?.name, t?.commit?.sha)).filter(t => !!t), rel)
    },
    async uploadAsset(repo, tag, name, data, contentType) {
      if (!isSafeTag(tag) || !ASSET_NAME_RE.test(name)) throw new ForgeError('E_FORGE_INPUT')
      let id: number
      try {
        const { data: r } = await withForgeRetry(() => forgeGetJson<{ id?: unknown }>(`${repoUrl(repo)}/releases/tags/${encodePath(tag)}`, req))
        if (typeof r?.id !== 'number') throw new ForgeError('E_FORGE_RESPONSE')
        id = r.id
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return 'no-release'
        throw err
      }
      const assets = await pages<{ name?: unknown }>(req, p => `${repoUrl(repo)}/releases/${id}/assets?limit=${PAGE}&page=${p}`, 200)
      if (assets.some(a => a?.name === name)) return 'exists'
      const mp = multipartFile('attachment', name, data, contentType)
      return sendOrExists(() => forgeSendJson(`${repoUrl(repo)}/releases/${id}/assets?name=${encodeURIComponent(name)}`, req,
        { method: 'POST', bytes: { data: mp.body, contentType: mp.contentType } }))
    },
  }
}

/** Chemin de téléversement GitHub : [/api/uploads]/repos/<owner>/<repo>/releases/<id>/assets. */
export function isUploadPath(pathname: string): boolean {
  const s = pathname.split('/')
  const rest = s[1] === 'api' && s[2] === 'uploads' ? s.slice(3) : s.slice(1)
  return s[0] === '' && rest.length === 6 && rest[0] === 'repos' && !!rest[1] && !!rest[2]
    && rest[3] === 'releases' && /^\d+$/.test(rest[4]!) && rest[5] === 'assets'
}

function github(access: ForgeAccess): ReleaseForge {
  const api = githubApiBase(access.base_url)
  const req: ForgeRequest = { token: access.token, authScheme: 'Bearer', accept: 'application/vnd.github+json', headers: { 'x-github-api-version': '2022-11-28' } }
  const repoUrl = (r: string) => `${api}/repos/${encodePath(checkFullName(r))}`
  // Hôte des téléversements : uploads.github.com pour github.com, la même instance sinon.
  const uploadOrigin = new URL(api).hostname === 'api.github.com' ? 'https://uploads.github.com' : new URL(api).origin
  return {
    async tags(repo, max = MAX_TAGS) {
      const raw = await pages<{ name?: unknown, commit?: { sha?: unknown } }>(req, p => `${repoUrl(repo)}/tags?per_page=100&page=${p}`, max, 100)
      const rel = await pages<RawRelease>(req, p => `${repoUrl(repo)}/releases?per_page=100&page=${p}`, max, 100)
      return mergeReleases(raw.map(t => toTag(t?.name, t?.commit?.sha)).filter(t => !!t), rel)
    },
    async uploadAsset(repo, tag, name, data, contentType) {
      if (!isSafeTag(tag) || !ASSET_NAME_RE.test(name)) throw new ForgeError('E_FORGE_INPUT')
      let rel: { upload_url?: unknown, assets?: { name?: unknown }[] }
      try {
        rel = (await withForgeRetry(() => forgeGetJson<typeof rel>(`${repoUrl(repo)}/releases/tags/${encodePath(tag)}`, req))).data ?? {}
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return 'no-release'
        throw err
      }
      if (Array.isArray(rel.assets) && rel.assets.some(a => a?.name === name)) return 'exists'
      const tmpl = str(rel.upload_url)
      if (!tmpl) throw new ForgeError('E_FORGE_RESPONSE')
      const target = new URL(tmpl.replace(/\{[^}]*\}$/, ''))
      // Jamais de jeton vers un autre hôte que celui des téléversements de cette forge.
      if (target.origin !== uploadOrigin || !isUploadPath(target.pathname)) throw new ForgeError('E_FORGE_URL')
      target.search = `name=${encodeURIComponent(name)}`
      return sendOrExists(() => forgeSendJson(target.toString(), req, { method: 'POST', bytes: { data, contentType } }))
    },
  }
}

function gitlab(access: ForgeAccess): ReleaseForge {
  const api = gitlabApiBase(access.base_url)
  const req = gitlabRequest(access)
  const proj = (r: string) => `${api}/projects/${gitlabProjectId(r)}`
  return {
    async tags(repo, max = MAX_TAGS) {
      const raw = await pages<{ name?: unknown, commit?: { id?: unknown } }>(req, p => `${proj(repo)}/repository/tags?per_page=100&page=${p}`, max, 100)
      const rel = await pages<RawRelease>(req, p => `${proj(repo)}/releases?per_page=100&page=${p}`, max, 100)
      return mergeReleases(raw.map(t => toTag(t?.name, t?.commit?.id)).filter(t => !!t), rel)
    },
    async uploadAsset(repo, tag, name, data, contentType) {
      if (!isSafeTag(tag) || !ASSET_NAME_RE.test(name)) throw new ForgeError('E_FORGE_INPUT')
      let links: { name?: unknown }[]
      try {
        const { data: r } = await withForgeRetry(() => forgeGetJson<{ assets?: { links?: { name?: unknown }[] } }>(`${proj(repo)}/releases/${encodeURIComponent(tag)}`, req))
        links = Array.isArray(r?.assets?.links) ? r.assets.links : []
      }
      catch (err) {
        if (err instanceof ForgeError && err.code === 'E_FORGE_NOT_FOUND') return 'no-release'
        throw err
      }
      if (links.some(l => l?.name === name)) return 'exists'
      const mp = multipartFile('file', name, data, contentType)
      const { data: up } = await withForgeRetry(() => forgeSendJson<{ full_path?: unknown }>(`${proj(repo)}/uploads`, req,
        { method: 'POST', bytes: { data: mp.body, contentType: mp.contentType } }))
      const path = str(up?.full_path)
      if (!path || !path.startsWith('/')) throw new ForgeError('E_FORGE_RESPONSE')
      return sendOrExists(() => forgeSendJson(`${proj(repo)}/releases/${encodeURIComponent(tag)}/assets/links`, req,
        { method: 'POST', json: { name, url: `${access.base_url}${path}`, link_type: 'other' } }))
    },
  }
}

/** Client « release » d'une forge (contrat 42). */
export function releaseForge(access: ForgeAccess): ReleaseForge {
  switch (access.kind) {
    case 'forgejo': return forgejo(access)
    case 'github': return github(access)
    case 'gitlab': return gitlab(access)
    default: throw new ForgeError('E_FORGE_UNSUPPORTED')
  }
}
