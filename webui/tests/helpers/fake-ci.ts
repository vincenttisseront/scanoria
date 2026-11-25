// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier C de la 0.8 : émetteur OIDC de test (clés RSA et EC, jetons signés,
// découverte et JWKS) et fausse forge en écriture pour la PR d'intégration
// (Forgejo, GitHub, GitLab), servis par un transport en mémoire
// (setForgeTransport) : aucune socket, chaque requête est enregistrée.

import { createHmac, generateKeyPairSync, sign as cryptoSign, type KeyObject } from 'node:crypto'
import { setForgeTransport, type FetchLike } from '../../server/forges/http'

export interface TestKey {
  kid: string
  alg: 'RS256' | 'ES256'
  privateKey: KeyObject
  jwk: Record<string, unknown>
}

export function rsaKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return { kid, alg: 'RS256', privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' } }
}

export function ecKey(kid: string): TestKey {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  return { kid, alg: 'ES256', privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'ES256' } }
}

const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url')

/** Jeton JWS compact signé par `key` (en-tête modifiable pour les cas hostiles). */
export function signJwt(key: TestKey, claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const h = { alg: key.alg, typ: 'JWT', kid: key.kid, ...header }
  const input = `${b64(h)}.${b64(claims)}`
  const sig = key.alg === 'RS256'
    ? cryptoSign('RSA-SHA256', Buffer.from(input), key.privateKey)
    : cryptoSign('SHA256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' })
  return `${input}.${sig.toString('base64url')}`
}

/** Jeton HS256 signé avec une clé publique comme secret HMAC (attaque par confusion). */
export function hs256WithPublicKey(key: TestKey, claims: Record<string, unknown>): string {
  const input = `${b64({ alg: 'HS256', typ: 'JWT', kid: key.kid })}.${b64(claims)}`
  const secret = JSON.stringify(key.jwk)
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`
}

export function unsignedJwt(claims: Record<string, unknown>): string {
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64(claims)}.`
}

export interface FakeIssuer {
  issuer: string
  keys: TestKey[]
  fetches: { discovery: number, jwks: number }
}

export interface FakeRequest { method: string, url: string, body: unknown }

type Handler = (req: FakeRequest) => { status: number, body?: unknown } | null

export interface FakeCi {
  issuers: Map<string, FakeIssuer>
  requests: FakeRequest[]
  addIssuer: (issuer: string, keys: TestKey[]) => FakeIssuer
  /** Routes de forge supplémentaires (tests) ; la première qui répond gagne. */
  handlers: Handler[]
  restore: () => void
}

function json(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

export function startFakeCi(): FakeCi {
  const f: FakeCi = {
    issuers: new Map(),
    requests: [],
    handlers: [],
    addIssuer(issuer, keys) {
      const i = { issuer, keys, fetches: { discovery: 0, jwks: 0 } }
      f.issuers.set(issuer, i)
      return i
    },
    restore: () => setForgeTransport(),
  }
  const transport: FetchLike = async (url, init) => {
    let body: unknown = null
    if (init.body instanceof Uint8Array) body = JSON.parse(Buffer.from(init.body).toString('utf8'))
    else if (typeof init.body === 'string') body = JSON.parse(init.body)
    const req = { method: init.method ?? 'GET', url, body }
    f.requests.push(req)
    for (const i of f.issuers.values()) {
      if (url === `${i.issuer}/.well-known/openid-configuration`) {
        i.fetches.discovery++
        return json(200, { issuer: i.issuer, jwks_uri: `${i.issuer}/.well-known/jwks` })
      }
      if (url === `${i.issuer}/.well-known/jwks`) {
        i.fetches.jwks++
        return json(200, { keys: i.keys.map(k => k.jwk) })
      }
    }
    for (const h of f.handlers) {
      const out = h(req)
      if (out) {
        if (typeof out.body === 'string') return new Response(out.body, { status: out.status })
        return json(out.status, out.body)
      }
    }
    return json(404, { message: 'not found' })
  }
  setForgeTransport(transport)
  return f
}

/** Revendications d'un jeton Forgejo/GitHub Actions valide pendant 5 minutes. */
export function actionsClaims(issuer: string, repository: string, ref: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: issuer, aud: 'scanoria', sub: `repo:${repository}:ref:${ref}`, iat: now, nbf: now, exp: now + 300,
    repository, ref, ref_type: ref.startsWith('refs/tags/') ? 'tag' : 'branch', run_id: '42', actor: 'dev-une', ...extra,
  }
}
