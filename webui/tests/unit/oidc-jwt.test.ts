// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J4 (0.8, chantier C) : lecture et vérification des jetons OIDC de CI, sans
// base ni réseau : jetons hostiles (alg none, HS256 avec la clé publique, kid
// inconnu, clé embarquée, signature d'une autre clé, jeton géant), contrôles
// temporels et d'audience, revendications par forge, motifs de ref.

import { describe, expect, it } from 'vitest'
import type { JwtError } from '../../server/ci/jwt'
import {
  CLOCK_SKEW_S, MAX_JWT_BYTES, candidateKeys, checkClaims, ciClaims, hasKid, jwkKey, parseJwt, refMatches, verifySignature,
} from '../../server/ci/jwt'
import { actionsClaims, ecKey, hs256WithPublicKey, rsaKey, signJwt, unsignedJwt } from '../helpers/fake-ci'

const ISS = 'https://forge.exemple.test/api/actions'
const rsa = rsaKey('k-rsa')
const ec = ecKey('k-ec')
const other = rsaKey('k-rsa')
const jwks = { keys: [rsa.jwk, ec.jwk] }

const code = (fn: () => unknown) => {
  try {
    fn()
  }
  catch (err) {
    return (err as JwtError).code
  }
  return 'ok'
}

function verify(token: string, set: unknown = jwks) {
  const jwt = parseJwt(token)
  verifySignature(jwt, candidateKeys(set, jwt.header))
  checkClaims(jwt.claims, { issuer: ISS, audience: 'scanoria', nowS: Math.floor(Date.now() / 1000) })
  return jwt
}

describe('oidc : jetons', () => {
  it('RS256 et ES256 valides', () => {
    expect(verify(signJwt(rsa, actionsClaims(ISS, 'equipe/app', 'refs/heads/main'))).header.alg).toBe('RS256')
    expect(verify(signJwt(ec, actionsClaims(ISS, 'equipe/app', 'refs/heads/main'))).header.alg).toBe('ES256')
  })

  it('refuse alg none, HS256 (clé publique comme secret), RS512 et l’absence d’alg', () => {
    const claims = actionsClaims(ISS, 'equipe/app', 'refs/heads/main')
    expect(code(() => verify(unsignedJwt(claims)))).toBe('E_OIDC_ALG')
    expect(code(() => verify(hs256WithPublicKey(rsa, claims)))).toBe('E_OIDC_ALG')
    expect(code(() => verify(signJwt(rsa, claims, { alg: 'RS512' })))).toBe('E_OIDC_ALG')
    expect(code(() => verify(signJwt(rsa, claims, { alg: undefined })))).toBe('E_OIDC_ALG')
  })

  it('refuse une clé embarquée ou désignée par URL (jwk, jku, x5u, x5c, crit)', () => {
    const claims = actionsClaims(ISS, 'equipe/app', 'refs/heads/main')
    for (const h of [{ jwk: other.jwk }, { jku: 'https://ailleurs.exemple.test/jwks' }, { x5u: 'https://ailleurs.exemple.test/c' }, { x5c: ['AAAA'] }, { crit: ['b64'] }]) {
      expect(code(() => verify(signJwt(other, claims, h)))).toBe('E_OIDC_MALFORMED')
    }
  })

  it('kid inconnu, signature d’une autre clé de même kid, ES256 présenté comme RS256', () => {
    const claims = actionsClaims(ISS, 'equipe/app', 'refs/heads/main')
    expect(code(() => verify(signJwt(rsa, claims, { kid: 'inconnu' })))).toBe('E_OIDC_KID')
    expect(code(() => verify(signJwt(other, claims)))).toBe('E_OIDC_SIGNATURE')
    // En-tête RS256 sur la clé EC : aucune clé compatible, refus.
    const forged = signJwt(ec, claims).split('.')
    forged[0] = Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'k-ec' })).toString('base64url')
    expect(code(() => verify(forged.join('.')))).toBe('E_OIDC_KID')
    // Sans kid : toutes les clés compatibles sont essayées, une seule suffit.
    expect(verify(signJwt(rsa, claims, { kid: undefined })).header.kid).toBeNull()
    expect(code(() => verify(signJwt(other, claims, { kid: undefined })))).toBe('E_OIDC_SIGNATURE')
  })

  it('jeton géant, mal formé, base64 invalide, charge non objet', () => {
    expect(code(() => parseJwt('a'.repeat(MAX_JWT_BYTES + 1)))).toBe('E_OIDC_TOO_LARGE')
    expect(code(() => parseJwt('a.b'))).toBe('E_OIDC_MALFORMED')
    expect(code(() => parseJwt('a.b.c.d'))).toBe('E_OIDC_MALFORMED')
    expect(code(() => parseJwt(`${Buffer.from('{"alg":"RS256"}').toString('base64url')}.e30.+++`))).toBe('E_OIDC_MALFORMED')
    expect(code(() => parseJwt(`${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from('[1]').toString('base64url')}.AAAA`))).toBe('E_OIDC_MALFORMED')
    expect(code(() => parseJwt(`${Buffer.from('{"alg":"RS256","kid":"\\u0000"}').toString('base64url')}.e30.AAAA`))).toBe('E_OIDC_KID')
    expect(code(() => parseJwt(42 as unknown as string))).toBe('E_OIDC_MALFORMED')
  })

  it('iss, aud (chaîne ou liste), exp, nbf, iat et durée de vie, avec tolérance d’horloge', () => {
    const nowS = Math.floor(Date.now() / 1000)
    const base = actionsClaims(ISS, 'equipe/app', 'refs/heads/main')
    const check = (c: Record<string, unknown>) => code(() => checkClaims({ ...base, ...c }, { issuer: ISS, audience: 'scanoria', nowS }))
    expect(check({})).toBe('ok')
    expect(check({ aud: ['autre', 'scanoria'] })).toBe('ok')
    expect(check({ iss: 'https://autre.exemple.test' })).toBe('E_OIDC_ISSUER')
    expect(check({ aud: 'https://forge.exemple.test/equipe' })).toBe('E_OIDC_AUDIENCE')
    expect(check({ aud: [1] })).toBe('E_OIDC_AUDIENCE')
    expect(check({ exp: undefined })).toBe('E_OIDC_CLAIMS')
    expect(check({ exp: nowS - CLOCK_SKEW_S - 1 })).toBe('E_OIDC_EXPIRED')
    expect(check({ exp: nowS - 10 })).toBe('ok')
    expect(check({ nbf: nowS + CLOCK_SKEW_S + 5 })).toBe('E_OIDC_NOT_YET_VALID')
    expect(check({ iat: nowS + CLOCK_SKEW_S + 5, nbf: undefined })).toBe('E_OIDC_NOT_YET_VALID')
    expect(check({ iat: nowS, exp: nowS + 3 * 24 * 3600 })).toBe('E_OIDC_LIFETIME')
  })

  it('revendications : GitHub/Forgejo (repository, ref), GitLab (project_path, ref courte, ref_type)', () => {
    expect(ciClaims('forgejo', actionsClaims(ISS, 'equipe/app', 'refs/tags/v1.2.0'))).toMatchObject({ repository: 'equipe/app', ref: 'refs/tags/v1.2.0', run: '42', actor: 'dev-une' })
    expect(ciClaims('gitlab', { project_path: 'groupe/sous/app', ref: 'main', ref_type: 'branch', pipeline_id: '7', user_login: 'dev' })).toMatchObject({ repository: 'groupe/sous/app', ref: 'refs/heads/main', run: '7' })
    expect(ciClaims('gitlab', { project_path: 'groupe/app', ref: 'v1', ref_type: 'tag' }).ref).toBe('refs/tags/v1')
    expect(code(() => ciClaims('gitlab', { project_path: 'groupe/app', ref: 'refs/heads/main', ref_type: 'branch' }))).toBe('E_OIDC_CLAIMS')
    expect(code(() => ciClaims('gitlab', { project_path: 'groupe/app', ref: 'main' }))).toBe('E_OIDC_CLAIMS')
    expect(code(() => ciClaims('github', { repository: '../etc', ref: 'refs/heads/main' }))).toBe('E_OIDC_CLAIMS')
    expect(code(() => ciClaims('github', { repository: 'equipe/app', ref: 'refs/heads/../main' }))).toBe('E_OIDC_CLAIMS')
    expect(code(() => ciClaims('github', { repository: 'equipe/app', ref: 'main' }))).toBe('E_OIDC_CLAIMS')
    expect(ciClaims('github', { repository: 'equipe/app', ref: 'refs/heads/main', run_id: 99, actor: '<script>' })).toMatchObject({ run: '99', actor: null })
  })

  it('motifs de ref : égalité, ou « * » final seulement', () => {
    expect(refMatches('refs/heads/main', 'refs/heads/main')).toBe(true)
    expect(refMatches('refs/heads/main', 'refs/heads/main2')).toBe(false)
    expect(refMatches('refs/tags/*', 'refs/tags/v1.0.0')).toBe(true)
    expect(refMatches('refs/tags/*', 'refs/tags/')).toBe(false)
    expect(refMatches('refs/tags/*', 'refs/heads/v1')).toBe(false)
    expect(refMatches('refs/*/main', 'refs/heads/main')).toBe(false)
    expect(refMatches('refs/heads/*x*', 'refs/heads/axb')).toBe(false)
  })

  it('JWK : type de clé et courbe vérifiés, RSA de moins de 2048 bits ignorée, usage chiffrement ignoré', () => {
    expect(jwkKey(rsa.jwk, 'ES256')).toBeNull()
    expect(jwkKey(ec.jwk, 'RS256')).toBeNull()
    expect(jwkKey({ ...ec.jwk, crv: 'P-384', alg: undefined }, 'ES256')).toBeNull()
    expect(jwkKey({ ...rsa.jwk, use: 'enc' }, 'RS256')).toBeNull()
    expect(jwkKey({ kty: 'RSA', n: 'AQAB', e: 'AQAB' }, 'RS256')).toBeNull()
    expect(jwkKey({ kty: 'oct', k: 'c2VjcmV0' } as never, 'RS256')).toBeNull()
    expect(candidateKeys({ keys: 'x' }, { alg: 'RS256', kid: null, typ: null })).toEqual([])
    expect(candidateKeys(null, { alg: 'RS256', kid: null, typ: null })).toEqual([])
    expect(hasKid(jwks, 'k-ec')).toBe(true)
    expect(hasKid(jwks, 'nope')).toBe(false)
    expect(hasKid(null, null)).toBe(true)
  })
})
