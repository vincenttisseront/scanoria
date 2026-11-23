// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/auth/password : changement de son propre mot de passe (mot de
// passe actuel exigé) ; les autres sessions du compte sont révoquées.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireAuth } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { setUserPassword, verifyUserPassword } from '../../utils/users'
import { revokeUserSessions } from '../../utils/sessions'
import { loginLimiter } from '../../utils/ratelimit'
import { changePasswordSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  const body = await readValidated(event, changePasswordSchema)
  const pool = getPool()
  const ip = clientAddress(event)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip }
  const limiterKey = `password:${auth.user.id}`
  if (!loginLimiter.hit(limiterKey)) throw apiError(429, 'E_RATE_LIMITED')
  if (!(await verifyUserPassword(pool, auth.user.id, body.current_password))) {
    await writeAudit(pool, { actor, action: 'auth.password-change', outcome: 'failure', targetType: 'user', targetId: String(auth.user.id) })
    throw apiError(400, 'E_CURRENT_PASSWORD')
  }
  if (body.current_password === body.new_password) {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'new_password', code: 'same_as_current' }] })
  }
  await setUserPassword(pool, auth.user.id, body.new_password, false)
  await revokeUserSessions(pool, auth.user.id, auth.tokenHash)
  loginLimiter.reset(limiterKey)
  await writeAudit(pool, { actor, action: 'auth.password-change', outcome: 'success', targetType: 'user', targetId: String(auth.user.id) })
  return { ok: true }
})
