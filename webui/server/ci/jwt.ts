// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J4 (0.8, chantier C) : lecture et vérification d'un jeton OIDC de CI (JWS
// compact). Fonctions pures, sans base ni réseau (node:crypto seulement), pour
// être testées aussi par tests/b39-ci.sh sans node_modules :
// - taille bornée, trois segments base64url stricts ;
// - algorithmes en liste fermée (RS256, ES256) : jamais « none » ni HS*, et
//   l'algorithme doit correspondre au type de la clé (aucune confusion RSA/HMAC) ;
// - iss, aud, exp, nbf (et iat) vérifiés avec une tolérance d'horloge bornée.
// Le jeton n'est jamais renvoyé dans une erreur : seulement un code.

import { createPublicKey, verify as cryptoVerify, type JsonWebKey, type KeyObject } from 'node:crypto'

/** Taille maximale d'un jeton présenté (les jetons des forges font 1 à 2 Kio). */
export const MAX_JWT_BYTES = 8 * 1024
/** Tolérance d'horloge entre la forge et l'appliance. */
export const CLOCK_SKEW_S = 60
/** Durée de vie maximale admise (exp - iat) : un jeton de CI vit quelques minutes. */
export const MAX_LIFETIME_S = 24 * 3600
export const ALLOWED_ALGS = ['RS256', 'ES256'] as const
export type JwtAlg = (typeof ALLOWED_ALGS)[number]

export type JwtErrorCode
  = | 'E_OIDC_MALFORMED' | 'E_OIDC_TOO_LARGE' | 'E_OIDC_ALG' | 'E_OIDC_KID' | 'E_OIDC_SIGNATURE'
    | 'E_OIDC_ISSUER' | 'E_OIDC_AUDIENCE' | 'E_OIDC_EXPIRED' | 'E_OIDC_NOT_YET_VALID' | 'E_OIDC_LIFETIME'
    | 'E_OIDC_CLAIMS' | 'E_OIDC_BINDING' | 'E_OIDC_REPOSITORY_ID' | 'E_OIDC_JWKS' | 'E_OIDC_DISABLED'

export class JwtError extends Error {
  // Sans propriété de paramètre : fichier chargeable par node --experimental-strip-types (b39).
  readonly code: JwtErrorCode
  constructor(code: JwtErrorCode) {
    super(code)
    this.code = code
    this.name = 'JwtError'
  }
}

export interface JwtHeader {
  alg: JwtAlg
  kid: string | null
  typ: string | null
}

export type JwtClaims = Record<string, unknown>

export interface ParsedJwt {
  header: JwtHeader
  claims: JwtClaims
  /** Octets signés (« en-tête.charge ») et signature décodée. */
  signingInput: Buffer
  signature: Buffer
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/
const KID_RE = /^[\x21-\x7e]{1,128}$/

function b64url(part: string): Buffer {
  if (!B64URL_RE.test(part) || part.length % 4 === 1) throw new JwtError('E_OIDC_MALFORMED')
  return Buffer.from(part, 'base64url')
}

function jsonObject(buf: Buffer): Record<string, unknown> {
  let v: unknown
  try {
    v = JSON.parse(buf.toString('utf8'))
  }
  catch {
    throw new JwtError('E_OIDC_MALFORMED')
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new JwtError('E_OIDC_MALFORMED')
  return v as Record<string, unknown>
}

/** Découpe un jeton compact sans rien lui accorder (aucune vérification de signature ici). */
export function parseJwt(raw: string): ParsedJwt {
  if (typeof raw !== 'string') throw new JwtError('E_OIDC_MALFORMED')
  if (Buffer.byteLength(raw, 'utf8') > MAX_JWT_BYTES) throw new JwtError('E_OIDC_TOO_LARGE')
  const parts = raw.split('.')
  if (parts.length !== 3 || !parts[0] || !parts[1]) throw new JwtError('E_OIDC_MALFORMED')
  const header = jsonObject(b64url(parts[0]))
  // L'algorithme d'abord : « none » (signature vide) est refusé comme tel.
  const alg = header.alg
  if (typeof alg !== 'string' || !(ALLOWED_ALGS as readonly string[]).includes(alg)) throw new JwtError('E_OIDC_ALG')
  const claims = jsonObject(b64url(parts[1]))
  if (!parts[2]) throw new JwtError('E_OIDC_MALFORMED')
  const signature = b64url(parts[2])
  // Aucune clé embarquée ni désignée par URL : seule la clé du JWKS de l'émetteur compte.
  if ('jwk' in header || 'jku' in header || 'x5u' in header || 'x5c' in header || 'crit' in header) throw new JwtError('E_OIDC_MALFORMED')
  const kid = header.kid
  if (kid !== undefined && (typeof kid !== 'string' || !KID_RE.test(kid))) throw new JwtError('E_OIDC_KID')
  const typ = typeof header.typ === 'string' ? header.typ : null
  return {
    header: { alg: alg as JwtAlg, kid: (kid as string | undefined) ?? null, typ },
    claims,
    signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
    signature,
  }
}

export interface Jwk {
  kty?: unknown
  kid?: unknown
  alg?: unknown
  use?: unknown
  crv?: unknown
  n?: unknown
  e?: unknown
  x?: unknown
  y?: unknown
}

/** Clé publique d'un JWK compatible avec l'algorithme, ou null (clé ignorée). */
export function jwkKey(jwk: Jwk, alg: JwtAlg): KeyObject | null {
  if (!jwk || typeof jwk !== 'object') return null
  if (jwk.use !== undefined && jwk.use !== 'sig') return null
  if (jwk.alg !== undefined && jwk.alg !== alg) return null
  let pub: JsonWebKey
  if (alg === 'RS256') {
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') return null
    pub = { kty: 'RSA', n: jwk.n, e: jwk.e }
  }
  else {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return null
    pub = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
  }
  try {
    const key = createPublicKey({ key: pub, format: 'jwk' })
    // RSA de moins de 2048 bits : refusée.
    if (alg === 'RS256' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) return null
    return key
  }
  catch {
    return null
  }
}

/**
 * Clés candidates d'un JWKS pour un en-tête : celle du `kid` s'il est donné
 * (absente → E_OIDC_KID), sinon toutes les clés compatibles.
 */
export function candidateKeys(jwks: unknown, header: JwtHeader): KeyObject[] {
  const keys = (jwks as { keys?: unknown } | null)?.keys
  if (!Array.isArray(keys)) return []
  const list = (keys as Jwk[]).slice(0, 50)
  const chosen = header.kid ? list.filter(k => k?.kid === header.kid) : list
  return chosen.map(k => jwkKey(k, header.alg)).filter((k): k is KeyObject => !!k)
}

export function hasKid(jwks: unknown, kid: string | null): boolean {
  if (!kid) return true
  const keys = (jwks as { keys?: unknown } | null)?.keys
  return Array.isArray(keys) && keys.some(k => (k as Jwk)?.kid === kid)
}

/** Vérifie la signature avec l'une des clés ; aucune → E_OIDC_SIGNATURE. */
export function verifySignature(jwt: ParsedJwt, keys: KeyObject[]): void {
  if (!keys.length) throw new JwtError(jwt.header.kid ? 'E_OIDC_KID' : 'E_OIDC_SIGNATURE')
  for (const key of keys) {
    const ok = jwt.header.alg === 'RS256'
      ? key.asymmetricKeyType === 'rsa' && cryptoVerify('RSA-SHA256', jwt.signingInput, key, jwt.signature)
      : key.asymmetricKeyType === 'ec' && jwt.signature.length === 64
        && cryptoVerify('SHA256', jwt.signingInput, { key, dsaEncoding: 'ieee-p1363' }, jwt.signature)
    if (ok) return
  }
  throw new JwtError('E_OIDC_SIGNATURE')
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

/** Contrôles temporels et d'audience, une fois la signature vérifiée. */
export function checkClaims(claims: JwtClaims, expected: { issuer: string, audience: string, nowS: number }): void {
  if (claims.iss !== expected.issuer) throw new JwtError('E_OIDC_ISSUER')
  const aud = claims.aud
  const auds = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud.filter((a): a is string => typeof a === 'string') : []
  if (!auds.includes(expected.audience)) throw new JwtError('E_OIDC_AUDIENCE')
  const exp = num(claims.exp)
  const nbf = num(claims.nbf)
  const iat = num(claims.iat)
  if (exp === null) throw new JwtError('E_OIDC_CLAIMS')
  if (exp + CLOCK_SKEW_S <= expected.nowS) throw new JwtError('E_OIDC_EXPIRED')
  if (nbf !== null && nbf - CLOCK_SKEW_S > expected.nowS) throw new JwtError('E_OIDC_NOT_YET_VALID')
  if (iat !== null && iat - CLOCK_SKEW_S > expected.nowS) throw new JwtError('E_OIDC_NOT_YET_VALID')
  if (exp - (iat ?? nbf ?? expected.nowS) > MAX_LIFETIME_S) throw new JwtError('E_OIDC_LIFETIME')
}

export type OidcKind = 'github' | 'gitlab' | 'forgejo'

export interface CiClaims {
  /** Dépôt « propriétaire/nom » (GitLab : chemin complet du projet). */
  repository: string
  /** Ref complète : refs/heads/… ou refs/tags/… (refs/pull/… pour une PR). */
  ref: string
  /** Identifiant immuable du dépôt (GitHub, Forgejo : repository_id ; GitLab : project_id), s'il est fourni. */
  repositoryId: string | null
  /** Identifiant lisible de l'exécution (journal d'audit), jamais le jeton. */
  run: string | null
  actor: string | null
}

const REPO_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+){1,9}$/
const REF_RE = /^refs\/[A-Za-z0-9._/-]{1,240}$/

const s = (v: unknown, max = 255): string | null => (typeof v === 'string' && v.length > 0 && v.length <= max ? v : null)
/** Identifiant numérique, en chaîne ou en nombre selon la forge. */
const numericId = (v: unknown): string | null => {
  if (typeof v === 'number' && Number.isSafeInteger(v) && v > 0) return String(v)
  return typeof v === 'string' && /^[1-9][0-9]{0,19}$/.test(v) ? v : null
}

/**
 * Revendications de dépôt et de ref propres à chaque forge :
 * - GitHub et Forgejo : `repository` (« owner/repo ») et `ref` complète ;
 * - GitLab : `project_path`, `ref` courte et `ref_type` (branch | tag).
 */
export function ciClaims(kind: OidcKind, claims: JwtClaims): CiClaims {
  let repository: string | null
  let ref: string | null
  if (kind === 'gitlab') {
    repository = s(claims.project_path)
    const short = s(claims.ref, 240)
    const type = claims.ref_type
    ref = short && !short.startsWith('refs/') && (type === 'branch' || type === 'tag')
      ? `refs/${type === 'branch' ? 'heads' : 'tags'}/${short}`
      : null
  }
  else {
    repository = s(claims.repository)
    ref = s(claims.ref, 250)
  }
  if (!repository || !REPO_RE.test(repository) || repository.split('/').some(x => x === '.' || x === '..') || !ref || !REF_RE.test(ref) || ref.split('/').includes('..')) throw new JwtError('E_OIDC_CLAIMS')
  const rawRun = kind === 'gitlab' ? claims.pipeline_id ?? claims.job_id : claims.run_id
  const run = s(rawRun, 40) ?? numericId(rawRun)
  const actor = s(kind === 'gitlab' ? claims.user_login : claims.actor, 100)
  return {
    repository,
    ref,
    repositoryId: numericId(kind === 'gitlab' ? claims.project_id : claims.repository_id),
    run: run && /^[A-Za-z0-9._-]+$/.test(run) ? run : null,
    actor: actor && /^[A-Za-z0-9._[\]-]+$/.test(actor) ? actor : null,
  }
}

/** Motif de ref d'une liaison : « * » à la fin seulement (refs/tags/*), sinon égalité. */
export function refMatches(pattern: string, ref: string): boolean {
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1)
    return !prefix.includes('*') && ref.startsWith(prefix) && ref.length > prefix.length
  }
  return !pattern.includes('*') && pattern === ref
}

export const REF_PATTERN_RE = /^refs\/[A-Za-z0-9._/-]{0,200}\*?$/
