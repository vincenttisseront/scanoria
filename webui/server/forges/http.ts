// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Requêtes vers une forge : HTTPS seulement, aucun identifiant dans l'URL,
// aucun hôte de bouclage ni lien local, délai, taille de réponse bornée,
// redirections suivies seulement vers le même hôte. Le jeton ne figure jamais
// dans une erreur : les messages ne portent qu'un code et un statut HTTP.

import { lookup as dnsLookup, type LookupAddress } from 'node:dns'
import { request as httpsRequest } from 'node:https'
import { Readable } from 'node:stream'
import { trimEnd } from '../utils/text'

export const FORGE_ERROR_CODES = [
  'E_FORGE_URL', 'E_FORGE_UNREACHABLE', 'E_FORGE_DNS', 'E_FORGE_BLOCKED', 'E_FORGE_TLS', 'E_FORGE_TIMEOUT', 'E_FORGE_AUTH', 'E_FORGE_NOT_FOUND',
  'E_FORGE_RATE_LIMITED', 'E_FORGE_TOO_LARGE', 'E_FORGE_REDIRECT', 'E_FORGE_RESPONSE',
  'E_FORGE_UNSUPPORTED', 'E_FORGE_INPUT',
] as const
export type ForgeErrorCode = (typeof FORGE_ERROR_CODES)[number]

export class ForgeError extends Error {
  /**
   * `detail` : code système de la cause réseau (ENOTFOUND, EPERM,
   * CERT_HAS_EXPIRED…), jamais un texte libre : il est affiché tel quel.
   */
  constructor(public readonly code: ForgeErrorCode, public readonly status: number | null = null, public readonly detail: string | null = null) {
    super(status ? `${code} (HTTP ${status})` : detail ? `${code} (${detail})` : code)
    this.name = 'ForgeError'
  }
}

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>

/**
 * Remplace le transport HTTP (tests seulement : faux serveurs de forge servis
 * en clair sur 127.0.0.1). Les contrôles d'URL s'appliquent avant, sur l'URL
 * logique en HTTPS. Sans argument, rétablit le transport HTTPS par défaut.
 */
export function setForgeTransport(fn?: FetchLike): void {
  transport = fn ?? httpsTransport
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

/** Adresse résolue à refuser : celles de forbiddenAddress, plus la multidiffusion. */
export function forbiddenResolvedAddress(address: string): boolean {
  const a = address.toLowerCase()
  return forbiddenAddress(a) || /^(22[4-9]|23\d)\./.test(a) || /^ff[0-9a-f]{2}:/.test(a)
}

class LookupRefused extends Error {
  readonly code = 'E_FORGE_RESOLVED_LOCAL'
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void
type LookupFn = (hostname: string, options: { all?: boolean, family?: number | string }, cb: LookupCb) => void

/**
 * Résolution DNS contrôlée : un nom qui résout vers une adresse refusée
 * (bouclage, lien local, multidiffusion) est refusé au moment même de la
 * connexion, sans second appel DNS qui pourrait répondre autre chose.
 */
function guardedLookup(refuse: (address: string) => boolean): LookupFn {
  return (hostname, options, cb) => {
    const f = options.family === 'IPv4' ? 4 : options.family === 'IPv6' ? 6 : Number(options.family) || 0
    dnsLookup(hostname, { family: f as 0 | 4 | 6, all: true }, (err, addresses) => {
      if (err) return cb(err, '')
      const list = addresses as LookupAddress[]
      if (!list.length || list.some(a => refuse(a.address))) return cb(new LookupRefused(hostname), '')
      if (options.all) cb(null, list)
      else cb(null, list[0]!.address, list[0]!.family)
    })
  }
}

export interface HttpsTransportOptions {
  /** Adresses résolues refusées (défaut : forbiddenResolvedAddress). */
  refuseAddress?: (address: string) => boolean
  /** AC supplémentaire (tests seulement). */
  ca?: string
}

/**
 * Transport HTTPS par node:https, avec la résolution contrôlée ci-dessus
 * (fetch ne permet pas de contrôler l'adresse résolue). Corps non compressé.
 */
export function createHttpsTransport(opts: HttpsTransportOptions = {}): FetchLike {
  const lookup = guardedLookup(opts.refuseAddress ?? forbiddenResolvedAddress)
  return (url, init) => new Promise<Response>((resolve, reject) => {
    const target = new URL(url)
    if (target.protocol !== 'https:') return reject(new ForgeError('E_FORGE_URL'))
    const headers: Record<string, string> = { 'accept-encoding': 'identity', ...(init.headers as Record<string, string> | undefined) }
    const req = httpsRequest(target, {
      method: init.method ?? 'GET',
      headers,
      lookup: lookup as never,
      signal: init.signal ?? undefined,
      ...(opts.ca ? { ca: opts.ca } : {}),
    }, (res) => {
      const status = res.statusCode ?? 0
      if (status < 200 || status > 599) {
        res.destroy()
        return reject(new ForgeError('E_FORGE_RESPONSE', status || null))
      }
      const h = new Headers()
      for (const [k, v] of Object.entries(res.headers)) {
        if (v === undefined) continue
        for (const x of Array.isArray(v) ? v : [v]) h.append(k, x)
      }
      const noBody = status === 204 || status === 205 || status === 304 || init.method === 'HEAD'
      if (noBody) res.resume()
      resolve(new Response(noBody ? null : Readable.toWeb(res) as ReadableStream, { status, headers: h }))
    })
    req.on('error', reject)
    const body = init.body
    if (body instanceof Uint8Array) req.end(Buffer.from(body))
    else if (typeof body === 'string') req.end(body)
    else req.end()
  })
}

export const httpsTransport: FetchLike = createHttpsTransport()

let transport: FetchLike = httpsTransport

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

const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EAI_NONAME', 'EAI_FAIL', 'EAI_NODATA', 'ENODATA'])
const BLOCKED_CODES = new Set(['EPERM', 'EACCES'])
const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT'])
const TLS_CODE_RE = /^(CERT_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_|ERR_TLS_|ERR_SSL_|ERR_CERT_)|^HOSTNAME_MISMATCH$|_CERT_|^EPROTO$/

/**
 * Traduit une erreur réseau en cause précise : DNS, sortie refusée sur
 * l'appliance (EPERM/EACCES : pare-feu local ou service sans droit réseau),
 * TLS, délai, ou forge injoignable (refus, aucune route). Le code système est
 * gardé en détail ; le message d'origine (qui peut contenir l'URL) jamais.
 */
export function classifyNetworkError(err: unknown): ForgeError {
  if (err instanceof ForgeError) return err
  const e = err as { name?: string, code?: unknown, cause?: { code?: unknown, name?: string } } | null
  const raw = typeof e?.code === 'string' ? e.code : typeof e?.cause?.code === 'string' ? e.cause.code : null
  const code = raw && /^[A-Z0-9_]{2,40}$/.test(raw) ? raw : null
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError' || e?.cause?.name === 'TimeoutError' || (code && TIMEOUT_CODES.has(code))) return new ForgeError('E_FORGE_TIMEOUT', null, code)
  if (code === 'E_FORGE_RESOLVED_LOCAL') return new ForgeError('E_FORGE_URL', null, 'RESOLVED_LOCAL')
  if (code && DNS_CODES.has(code)) return new ForgeError('E_FORGE_DNS', null, code)
  if (code && BLOCKED_CODES.has(code)) return new ForgeError('E_FORGE_BLOCKED', null, code)
  if (code && TLS_CODE_RE.test(code)) return new ForgeError('E_FORGE_TLS', null, code)
  return new ForgeError('E_FORGE_UNREACHABLE', null, code)
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
      throw classifyNetworkError(err)
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
    let body: Buffer
    try {
      body = await readBounded(res, req.maxBytes ?? DEFAULT_MAX_BYTES)
    }
    catch (err) {
      throw classifyNetworkError(err)
    }
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

export interface ForgeSendOptions {
  method: 'POST' | 'PATCH' | 'PUT' | 'DELETE'
  /** Corps JSON (sérialisé ici, borné). */
  json?: unknown
  /** Statuts attendus en plus de 2xx (ex. 404 pour « déjà supprimé »). */
  allowStatus?: number[]
}

/** Corps envoyé au plus : un commentaire ou une revue, jamais un fichier. */
export const MAX_SEND_BYTES = 512 * 1024

/**
 * Écriture authentifiée (statut de commit, commentaire, revue, webhook) : mêmes
 * contrôles que forgeGet, mais aucune redirection n'est suivie (le corps et le
 * jeton ne partent jamais ailleurs que vers l'URL demandée).
 */
export async function forgeSend(url: string, req: ForgeRequest, opts: ForgeSendOptions): Promise<ForgeResponse> {
  const target = new URL(url)
  if (target.protocol !== 'https:' || target.username || target.password) throw new ForgeError('E_FORGE_URL')
  const payload = opts.json === undefined ? undefined : Buffer.from(JSON.stringify(opts.json), 'utf8')
  if (payload && payload.length > MAX_SEND_BYTES) throw new ForgeError('E_FORGE_INPUT')
  const headers: Record<string, string> = {
    'accept': req.accept ?? 'application/json',
    'user-agent': 'scanoria-console',
    ...req.headers,
  }
  if (payload) {
    headers['content-type'] = 'application/json'
    headers['content-length'] = String(payload.length)
  }
  if (req.token) headers.authorization = `${req.authScheme} ${req.token}`
  let res: Response
  try {
    res = await transport(target.toString(), {
      method: opts.method,
      headers,
      body: payload ? new Uint8Array(payload) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(req.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    })
  }
  catch (err) {
    throw classifyNetworkError(err)
  }
  const allowed = opts.allowStatus ?? []
  if (res.status >= 300 && res.status < 400) {
    await res.body?.cancel().catch(() => {})
    throw new ForgeError('E_FORGE_REDIRECT', res.status)
  }
  if (!allowed.includes(res.status)) {
    if (rateLimited(res)) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_RATE_LIMITED', res.status)
    }
    if (res.status === 401 || res.status === 403) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_AUTH', res.status)
    }
    if (res.status === 404) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_NOT_FOUND', 404)
    }
    if (res.status < 200 || res.status >= 300) {
      await res.body?.cancel().catch(() => {})
      throw new ForgeError('E_FORGE_RESPONSE', res.status)
    }
  }
  let body: Buffer
  try {
    body = await readBounded(res, req.maxBytes ?? DEFAULT_MAX_BYTES)
  }
  catch (err) {
    throw classifyNetworkError(err)
  }
  return { status: res.status, headers: res.headers, body }
}

export async function forgeSendJson<T = unknown>(url: string, req: ForgeRequest, opts: ForgeSendOptions): Promise<{ data: T | null, status: number }> {
  const res = await forgeSend(url, req, opts)
  if (!res.body.length) return { data: null, status: res.status }
  try {
    return { data: JSON.parse(res.body.toString('utf8')) as T, status: res.status }
  }
  catch {
    throw new ForgeError('E_FORGE_RESPONSE', res.status)
  }
}

/** Délais de recul entre deux essais (tests : setForgeRetryDelays([0, 0])). */
let retryDelays = [500, 2000]
export function setForgeRetryDelays(delays?: number[]): void {
  retryDelays = delays ?? [500, 2000]
}

/** Erreur passagère : réseau, délai, quota, erreur 5xx de la forge. */
export function transientForgeError(err: unknown): boolean {
  if (!(err instanceof ForgeError)) return false
  return err.code === 'E_FORGE_TIMEOUT' || err.code === 'E_FORGE_UNREACHABLE' || err.code === 'E_FORGE_RATE_LIMITED'
    || (err.code === 'E_FORGE_RESPONSE' && (err.status ?? 0) >= 500)
}

/** Réessaie une opération sur erreur passagère, avec recul (deux essais de plus au plus). */
export async function withForgeRetry<T>(fn: () => Promise<T>): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn()
    }
    catch (err) {
      if (!transientForgeError(err) || attempt >= retryDelays.length) throw err
      await new Promise(r => setTimeout(r, retryDelays[attempt]))
    }
  }
}
