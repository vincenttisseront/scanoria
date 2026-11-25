// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 41 (0.8, chantier C) : authenticateCi(event) → {projectId, scopes,
// identity}. Deux preuves acceptées sur les routes de la CI :
// - le jeton d'API par projet (« scn_… », inchangé depuis la 0.3) ;
// - un jeton OIDC de la CI (J4), vérifié par server/ci/oidc.ts et rattaché à
//   un projet par une liaison (dépôt, ref).
// L'identité est toujours NON HUMAINE : elle peut demander une exception,
// jamais l'approuver (J15). Chaque refus OIDC est compté et audité, sans
// jamais journaliser le jeton.

import { getHeader, type H3Event } from 'h3'
import type { Queryable } from '../utils/db'
import { clientAddress } from '../utils/http'
import { writeAudit } from '../utils/audit'
import { FixedWindowLimiter } from '../utils/ratelimit'
import { verifyApiToken } from '../gates/tokens'
import { gateError } from '../gates/http'
import { API_TOKEN_RE } from '#shared/analysis'
import { OidcRefusal, verifyOidcToken } from './oidc'
import { JwtError, type JwtErrorCode } from './jwt'

export interface CiIdentity {
  kind: 'api-token' | 'oidc'
  /** Libellé d'audit : « api-token:scn_abcd » ou « oidc:<dépôt>@<ref> ». */
  label: string
  isHuman: false
}

export interface CiAuth {
  projectId: string
  scopes: string[]
  identity: CiIdentity
  /** Jeton d'API utilisé (null pour OIDC) : colonne scans.api_token_id. */
  apiTokenId: string | null
  /** Préfixe affiché (jeton d'API) ou « oidc ». */
  prefix: string
}

declare module 'h3' {
  interface H3EventContext {
    /** Appel de CI authentifié (contrat 41), posé par server/middleware/api-token.ts. */
    ciAuth?: CiAuth
  }
}

export class CiAuthError extends Error {
  constructor(public readonly status: 401 | 403, public readonly code: 'E_TOKEN_INVALID' | 'E_TOKEN_REVOKED' | 'E_TOKEN_EXPIRED' | 'E_TOKEN_SCOPE', public readonly reason: string) {
    super(code)
    this.name = 'CiAuthError'
  }
}

/** Refus OIDC par raison, depuis le démarrage (photographie de santé, tests). */
const refusals = new Map<string, number>()
export function oidcRefusalCounts(): Record<string, number> {
  return Object.fromEntries(refusals)
}
export function resetOidcRefusalCounts(): void {
  refusals.clear()
}

/** Forme d'un JWS compact (trois segments base64url), sans rien vérifier. */
const JWT_SHAPE_RE = /^[\w-]+\.[\w-]+\.[\w-]*$/

function bearer(event: H3Event): string | null {
  const authz = getHeader(event, 'authorization')
  if (!authz || !/^bearer\s/i.test(authz)) return null
  return authz.replace(/^bearer\s+/i, '').trim()
}

/**
 * Lignes d'audit de refus par adresse : bornées avant tout limiteur de
 * réponse, pour qu'un flot de faux jetons n'inonde pas le journal. Les refus
 * restent tous comptés.
 */
export const refusalAuditLimiter = new FixedWindowLimiter(30, 10 * 60_000)

async function refuseOidc(db: Queryable, event: H3Event, code: JwtErrorCode, ctx: { issuer?: string, repository?: string, ref?: string }, projectId: string | null): Promise<never> {
  refusals.set(code, (refusals.get(code) ?? 0) + 1)
  const status = code === 'E_OIDC_BINDING' || code === 'E_OIDC_REPOSITORY_ID' ? 403 : 401
  if (!refusalAuditLimiter.hit(clientAddress(event) ?? 'unknown')) throw new CiAuthError(status, status === 403 ? 'E_TOKEN_SCOPE' : 'E_TOKEN_INVALID', code)
  let host: string | null
  try {
    host = ctx.issuer ? new URL(ctx.issuer).host : null
  }
  catch {
    host = null
  }
  await writeAudit(db, {
    actor: { type: 'anonymous', username: 'oidc', ip: clientAddress(event) },
    action: 'ci.oidc-refuse',
    outcome: 'denied',
    targetType: projectId ? 'project' : null,
    targetId: projectId,
    details: { reason: code, issuer: host, repository: ctx.repository ?? null, ref: ctx.ref ?? null },
  }).catch(() => {})
  throw new CiAuthError(status, status === 403 ? 'E_TOKEN_SCOPE' : 'E_TOKEN_INVALID', code)
}

/**
 * Authentifie un appel de CI. `projectId` : projet de la route (null pour une
 * route sans projet, comme le verdict : un jeton OIDC doit alors se rattacher
 * à un seul projet). Le résultat est gardé dans event.context.ciAuth.
 */
export async function authenticateCi(event: H3Event, db: Queryable, projectId: string | null = null, now = Date.now()): Promise<CiAuth> {
  if (event.context.ciAuth) return event.context.ciAuth
  const presented = bearer(event)
  if (!presented) throw new CiAuthError(401, 'E_TOKEN_INVALID', 'missing')

  let auth: CiAuth
  if (API_TOKEN_RE.test(presented) || !JWT_SHAPE_RE.test(presented)) {
    const check = await verifyApiToken(db, presented)
    if (!check.ok) throw new CiAuthError(401, check.code, check.code)
    if (projectId && projectId !== check.token.projectId) throw new CiAuthError(403, 'E_TOKEN_SCOPE', 'project')
    auth = {
      projectId: check.token.projectId,
      scopes: check.token.scopes,
      identity: { kind: 'api-token', label: `api-token:${check.token.prefix}`, isHuman: false },
      apiTokenId: check.token.id,
      prefix: check.token.prefix,
    }
  }
  else {
    let res
    try {
      res = await verifyOidcToken(db, presented, now)
    }
    catch (err) {
      if (err instanceof OidcRefusal) return refuseOidc(db, event, err.code, err.context, projectId)
      if (err instanceof JwtError) return refuseOidc(db, event, err.code, {}, projectId)
      throw err
    }
    const match = projectId
      ? res.matches.find(m => m.projectId === projectId)
      : res.matches.length === 1 ? res.matches[0] : undefined
    if (!match) return refuseOidc(db, event, 'E_OIDC_BINDING', { issuer: res.issuer, repository: res.claims.repository, ref: res.claims.ref }, projectId)
    auth = {
      projectId: match.projectId,
      scopes: match.scopes,
      identity: { kind: 'oidc', label: `oidc:${res.claims.repository}@${res.claims.ref}`.slice(0, 255), isHuman: false },
      apiTokenId: null,
      prefix: 'oidc',
    }
  }
  event.context.ciAuth = auth
  return auth
}

/** Erreur HTTP d'un refus (codes stables des gates, sans la raison détaillée). */
export function ciAuthHttpError(err: CiAuthError) {
  return gateError(err.status, err.code)
}
