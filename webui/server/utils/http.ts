// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aides HTTP : erreurs à code stable (traduites par le client), lecture
// validée par zod, contrôle d'authentification et de rôle, adresse cliente.

import { createError, getHeader, readBody, getQuery, type H3Event } from 'h3'
import type { z } from 'zod'
import { getConfig } from './config'
import { resolveClientAddress } from './client-ip'
import { RequestTooLargeError, RequestValidationError } from './requests'
import type { SessionUser } from './sessions'
import { hasRole, type Role } from '#shared/schemas'

export interface AuthContext {
  user: SessionUser
  tokenHash: string
  csrf: string
}

declare module 'h3' {
  interface H3EventContext {
    auth?: AuthContext
    clientAddress?: string
  }
}

export type ApiErrorCode
  = | 'E_UNAUTHENTICATED' | 'E_FORBIDDEN' | 'E_CSRF' | 'E_ORIGIN' | 'E_VALIDATION' | 'E_NOT_FOUND'
    | 'E_INVALID_CREDENTIALS' | 'E_RATE_LIMITED' | 'E_PASSWORD_CHANGE_REQUIRED' | 'E_USERNAME_TAKEN'
    | 'E_LAST_ADMIN' | 'E_SELF' | 'E_CURRENT_PASSWORD' | 'E_HELPER_BUSY' | 'E_STATE_UNAVAILABLE'
    | 'E_NO_PREVIOUS' | 'E_NO_UPDATE' | 'E_TOO_LARGE' | 'E_UPLOAD' | 'E_UNAVAILABLE' | 'E_INTERNAL'
    | 'E_CATALOG_UNAVAILABLE' | 'E_PLAN' | 'E_NOT_INSTALLED' | 'E_DEPENDENTS'
    | 'E_MALICIOUS' | 'E_NOT_SECRET' | 'E_AI_STALE'
    | 'E_NOT_PERMANENT' | 'E_BACKUP_NOT_FOUND' | 'E_BACKUP_INVALID'

export function apiError(statusCode: number, code: ApiErrorCode, extra: Record<string, unknown> = {}) {
  return createError({ statusCode, statusMessage: code, data: { code, ...extra } })
}

/** Lit et valide le corps JSON ; 400 E_VALIDATION avec les chemins fautifs (jamais les valeurs). */
export async function readValidated<S extends z.ZodType>(event: H3Event, schema: S): Promise<z.infer<S>> {
  let body: unknown
  try {
    body = await readBody(event)
  }
  catch {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: '', code: 'invalid_json' }] })
  }
  const parsed = schema.safeParse(body ?? {})
  if (!parsed.success) {
    throw apiError(400, 'E_VALIDATION', {
      issues: parsed.error.issues.slice(0, 20).map(i => ({ path: i.path.join('.'), code: i.code })),
    })
  }
  return parsed.data
}

export function queryValidated<S extends z.ZodType>(event: H3Event, schema: S): z.infer<S> {
  const parsed = schema.safeParse(getQuery(event))
  if (!parsed.success) {
    throw apiError(400, 'E_VALIDATION', {
      issues: parsed.error.issues.slice(0, 20).map(i => ({ path: i.path.join('.'), code: i.code })),
    })
  }
  return parsed.data
}

export function requireAuth(event: H3Event): AuthContext {
  const auth = event.context.auth
  if (!auth) throw apiError(401, 'E_UNAUTHENTICATED')
  return auth
}

export function requireRole(event: H3Event, role: Role): AuthContext {
  const auth = requireAuth(event)
  if (!hasRole(auth.user.role, role)) throw apiError(403, 'E_FORBIDDEN')
  return auth
}

export function clientAddress(event: H3Event): string | undefined {
  if (!('clientAddress' in event.context)) {
    event.context.clientAddress = resolveClientAddress(
      event.node.req.socket?.remoteAddress,
      getHeader(event, 'x-real-ip'),
      getConfig().trustProxy,
    )
  }
  return event.context.clientAddress
}

export function idParam(raw: string | undefined): number {
  const n = Number(raw)
  if (!raw || !/^[0-9]{1,15}$/.test(raw) || !Number.isSafeInteger(n) || n <= 0) throw apiError(404, 'E_NOT_FOUND')
  return n
}

/** Convertit les erreurs de dépôt de demande en erreurs HTTP. */
export function mapRequestError(err: unknown): never {
  if (err instanceof RequestValidationError) throw apiError(400, 'E_VALIDATION', { issues: err.issues })
  if (err instanceof RequestTooLargeError) throw apiError(413, 'E_TOO_LARGE')
  throw err
}
