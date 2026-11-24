// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Requêtes vers une forge : HTTPS seulement, aucun identifiant dans l'URL,
// aucun hôte de bouclage ni lien local, délai, taille de réponse bornée,
// redirections suivies seulement vers le même hôte. Le jeton ne figure jamais
// dans une erreur : les messages ne portent qu'un code et un statut HTTP.

import { trimEnd } from '../utils/text'

export const FORGE_ERROR_CODES = [
  'E_FORGE_URL', 'E_FORGE_UNREACHABLE', 'E_FORGE_TIMEOUT', 'E_FORGE_AUTH', 'E_FORGE_NOT_FOUND',
  'E_FORGE_RATE_LIMITED', 'E_FORGE_TOO_LARGE', 'E_FORGE_REDIRECT', 'E_FORGE_RESPONSE',
  'E_FORGE_UNSUPPORTED', 'E_FORGE_INPUT',
] as const
export type ForgeErrorCode = (typeof FORGE_ERROR_CODES)[number]

export class ForgeError extends Error {
  constructor(public readonly code: ForgeErrorCode, public readonly status: number | null = null) {
    super(status ? `${code} (HTTP ${status})` : code)
    this.name = 'ForgeError'
  }
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>

let transport: FetchLike = (url, init) => fetch(url, init)

/**
 * Remplace le transport HTTP (tests seulement : faux serveurs de forge servis
 * en clair sur 127.0.0.1). Les contrôles d'URL s'appliquent avant, sur l'URL
 * logique en HTTPS. Sans argument, rétablit fetch.
 */
export function setForgeTransport(fn?: FetchLike): void {
  transport = fn ?? ((url, init) => fetch(url, init))
}

const LOOPBACK_HOST_RE = /^(localhost|.+\.localhost|localhost\.localdomain|ip6-localhost|ip6-loopback)$/i

/** Adresse littérale à refuser : bouclage, non spécifiée, lien local. */
function forbiddenAddress(host: string): boolean {
  let h = trimEnd(host.replace(/^\[|\]$/g, ''), '.').toLowerCase()
  // IPv4 mappée en IPv6 sous forme hexadécimale (::ffff:7f00:1, que produit
  // la normalisation de l'URL) : ramenée à la forme pointée.
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h)
  if (mapped) {
    const hi = Number.parseInt(mapped[1]!, 16)
    const lo = Number.parseInt(mapped[2]!, 16)
    h = `::ffff:${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`
  }
  if (/^127\./.test(h) || /^0\./.test(h) || h === '0.0.0.0' || /^169\.254\./.test(h)) return true
  if (h === '::' || h === '::1' || /^fe[89ab][0-9a-f]:/.test(h) || /^::ffff:(127|0|169\.254)\./.test(h)) return true
  return false
}

/**
 * Valide l'URL de base d'une forge et la normalise (sans « / » final).
 * Refuse tout schéma autre que https (file://, ext::, ssh…), les identifiants,
 * la requête, le fragment, le bouclage et les liens locaux.
 */
export function normalizeBaseUrl(raw: string): string {
  let u: URL
  try {
    u = new URL(raw.trim())
  }
  catch {
    throw new ForgeError('E_FORGE_URL')
  }
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || raw.includes('@')) throw new ForgeError('E_FORGE_URL')
  if (!u.hostname || LOOPBACK_HOST_RE.test(trimEnd(u.hostname, '.')) || forbiddenAddress(u.hostname)) throw new ForgeError('E_FORGE_URL')
  if (raw.length > 512) throw new ForgeError('E_FORGE_URL')
  const path = trimEnd(u.pathname, '/')
  if (path.split('/').some(s => s === '..' || s === '.')) throw new ForgeError('E_FORGE_URL')
  return `${u.protocol}//${u.host}${path}`
}

export interface ForgeRequest {
  token?: string | null
  /** En-tête d'authentification (« token » pour Forgejo, « Bearer » pour GitHub). */
  authScheme: 'token' | 'Bearer'
  accept?: string
  timeoutMs?: number
  maxBytes?: number
  headers?: Record<string, string>
}

export interface ForgeResponse {
  status: number
  headers: Headers
  body: Buffer
}

export const DEFAULT_TIMEOUT_MS = 15_000
export const DEFAULT_MAX_BYTES = 8 * 1024 * 1024
const MAX_REDIRECTS = 3

async function readBounded(res: Response, maxBytes: number): Promise<Buffer> {
  const declared = Number(res.headers.get('content-length') ?? '0')
  if (declared > maxBytes) {
    await res.body?.cancel().catch(() => {})
    throw new ForgeError('E_FORGE_TOO_LARGE', res.status)
  }
  if (!res.body) return Buffer.alloc(0)
  const reader = res.body.getReader()
  const chunks: Buffer[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_TOO_LARGE', res.status)
    }
    chunks.push(Buffer.from(value))
  }
  return Buffer.concat(chunks)
}

function rateLimited(res: Response): boolean {
  return res.status === 429 || (res.status === 403 && res.headers.get('x-ratelimit-remaining') === '0')
}

/**
 * GET authentifié avec contrôles. 404 → E_FORGE_NOT_FOUND ; 401/403 →
 * E_FORGE_AUTH ; 429 (ou quota GitHub épuisé) → E_FORGE_RATE_LIMITED.
 * `allowNotFound` renvoie la réponse 404 au lieu de lever.
 */
export async function forgeGet(url: string, req: ForgeRequest, opts: { allowNotFound?: boolean } = {}): Promise<ForgeResponse> {
  let current = new URL(url)
  if (current.protocol !== 'https:' || current.username || current.password) throw new ForgeError('E_FORGE_URL')
  const origin = current.origin
  for (let hop = 0; ; hop++) {
    const headers: Record<string, string> = {
      'accept': req.accept ?? 'application/json',
      'user-agent': 'scanoria-console',
      ...req.headers,
    }
    if (req.token) headers.authorization = `${req.authScheme} ${req.token}`
    let res: Response
    try {
      res = await transport(current.toString(), {
        method: 'GET',
        headers,
        redirect: 'manual',
        signal: AbortSignal.timeout(req.timeoutMs ?? DEFAULT_TIMEOUT_MS),
      })
    }
    catch (err) {
      const name = (err as Error)?.name
      throw new ForgeError(name === 'TimeoutError' || name === 'AbortError' ? 'E_FORGE_TIMEOUT' : 'E_FORGE_UNREACHABLE')
    }
    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      await res.body?.cancel().catch(() => {})
      let next: URL
      try {
        next = new URL(res.headers.get('location')!, current)
      }
      catch {
        throw new ForgeError('E_FORGE_REDIRECT', res.status)
      }
      // Jamais vers un autre hôte ni en clair : le jeton suivrait.
      if (next.origin !== origin || next.username || next.password || hop >= MAX_REDIRECTS) throw new ForgeError('E_FORGE_REDIRECT', res.status)
      current = next
      continue
    }
    if (rateLimited(res)) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_RATE_LIMITED', res.status)
    }
    if (res.status === 401 || res.status === 403) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_AUTH', res.status)
    }
    if (res.status === 404 && !opts.allowNotFound) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_NOT_FOUND', 404)
    }
    if (res.status !== 404 && (res.status < 200 || res.status >= 300)) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_RESPONSE', res.status)
    }
    const body = await readBounded(res, req.maxBytes ?? DEFAULT_MAX_BYTES)
    return { status: res.status, headers: res.headers, body }
  }
}

export async function forgeGetJson<T = unknown>(url: string, req: ForgeRequest): Promise<{ data: T, headers: Headers }> {
  const res = await forgeGet(url, req)
  try {
    return { data: JSON.parse(res.body.toString('utf8')) as T, headers: res.headers }
  }
  catch {
    throw new ForgeError('E_FORGE_RESPONSE', res.status)
  }
}
