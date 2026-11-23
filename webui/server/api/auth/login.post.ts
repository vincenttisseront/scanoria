// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/auth/login : compte local. Limitation par adresse (20 / 10 min),
// verrouillage du compte après N échecs, réponse identique pour tout échec.

import { defineEventHandler, getHeader, setCookie, setHeader } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, clientAddress, readValidated } from '../../utils/http'
import { getAuthSettings } from '../../utils/settings'
import { authenticate } from '../../utils/users'
import { writeAudit } from '../../utils/audit'
import { loginLimiter } from '../../utils/ratelimit'
import { SESSION_COOKIE, createSession, csrfTokenFor, revokeSession } from '../../utils/sessions'
import { loginSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const ip = clientAddress(event)
  const limiterKey = ip ?? 'unknown'
  if (!loginLimiter.hit(limiterKey)) {
    setHeader(event, 'retry-after', loginLimiter.retryAfterSeconds(limiterKey))
    throw apiError(429, 'E_RATE_LIMITED')
  }
  const body = await readValidated(event, loginSchema)
  const username = body.username.trim().toLowerCase()
  const pool = getPool()
  const settings = await getAuthSettings(pool)
  const outcome = await authenticate(pool, username, body.password, settings)
  if (!outcome.ok) {
    await writeAudit(pool, {
      actor: { type: 'anonymous', userId: outcome.userId ?? null, username: username.slice(0, 64), ip },
      action: 'auth.login',
      outcome: 'failure',
      targetType: 'user',
      targetId: outcome.userId ? String(outcome.userId) : null,
      details: { reason: outcome.reason, locked_now: outcome.lockedNow ?? false },
    })
    throw apiError(401, 'E_INVALID_CREDENTIALS')
  }
  if (event.context.auth) await revokeSession(pool, event.context.auth.tokenHash)
  const { token, expiresAt } = await createSession(pool, outcome.userId, settings, {
    ip,
    userAgent: getHeader(event, 'user-agent') ?? null,
  })
  setCookie(event, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    expires: expiresAt,
  })
  await writeAudit(pool, {
    actor: { type: 'user', userId: outcome.userId, username: outcome.username, ip },
    action: 'auth.login',
    outcome: 'success',
    targetType: 'user',
    targetId: String(outcome.userId),
  })
  return { ok: true, csrf: csrfTokenFor(token) }
})
