// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Erreurs à code stable propres aux quality gates et à l'API de la CI
// (traduites côté console sous gates.errors.*), et contexte du jeton d'API.

import { createError, type H3Event } from 'h3'
import { apiError, requireAuth, requireRole, type AuthContext } from '../utils/http'
import type { Role } from '#shared/schemas'

export type GateErrorCode
  = | 'E_TOKEN_INVALID' | 'E_TOKEN_REVOKED' | 'E_TOKEN_EXPIRED' | 'E_TOKEN_SCOPE'
    | 'E_GATE_IN_USE' | 'E_GATE_BUILTIN' | 'E_SLUG_TAKEN' | 'E_PROJECT_ARCHIVED' | 'E_SCAN_REFUSED'

export function gateError(statusCode: number, code: GateErrorCode, extra: Record<string, unknown> = {}) {
  return createError({ statusCode, statusMessage: code, data: { code, ...extra } })
}

export interface ApiTokenContext {
  /** Identifiant du jeton d'API, ou libellé de l'identité OIDC (J4, 0.8). */
  id: string
  /** Ligne de api_tokens (null pour un jeton OIDC) : colonnes *.api_token_id. */
  apiTokenId?: string | null
  projectId: string
  scopes: string[]
  prefix: string
  /** Libellé d'audit (contrat 41) : « api-token:scn_abcd » ou « oidc:<dépôt>@<ref> ». */
  label?: string
}

/** Colonne api_token_id d'un appel de CI (null pour OIDC). */
export function tokenRowId(token: ApiTokenContext): string | null {
  return token.apiTokenId === undefined ? token.id : token.apiTokenId
}

/** Libellé d'audit d'un appel de CI (identité non humaine). */
export function tokenLabel(token: ApiTokenContext): string {
  return token.label ?? `api-token:${token.prefix}`
}

declare module 'h3' {
  interface H3EventContext {
    /** Jeton d'API vérifié par server/middleware/api-token.ts. */
    apiToken?: ApiTokenContext
    /** Route publique déclarée par server/middleware/api-token.ts (badge, client). */
    gatesPublic?: boolean
  }
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function uuidParam(raw: string | undefined): string {
  if (!raw || !UUID_RE.test(raw)) throw apiError(404, 'E_NOT_FOUND')
  return raw.toLowerCase()
}

export type Caller
  = | { kind: 'token', token: ApiTokenContext }
    | { kind: 'user', auth: AuthContext }

/**
 * Appelant d'une route de la CI : jeton d'API (portée et projet vérifiés) ou
 * session d'une personne ayant au moins le rôle demandé.
 */
export function ciCaller(event: H3Event, scope: 'scan:create' | 'scan:read', role: Role): Caller {
  const token = event.context.apiToken
  if (token) {
    if (!token.scopes.includes(scope)) throw gateError(403, 'E_TOKEN_SCOPE')
    return { kind: 'token', token }
  }
  return { kind: 'user', auth: role === 'viewer' ? requireAuth(event) : requireRole(event, role) }
}
