// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/auth/logout : révoque la session courante et efface le cookie.

import { defineEventHandler, deleteCookie } from 'h3'
import { getPool } from '../../utils/db'
import { clientAddress, requireAuth } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { SESSION_COOKIE, revokeSession } from '../../utils/sessions'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  const pool = getPool()
  await revokeSession(pool, auth.tokenHash)
  deleteCookie(event, SESSION_COOKIE, { httpOnly: true, secure: true, sameSite: 'strict', path: '/' })
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'auth.logout',
    outcome: 'success',
    targetType: 'user',
    targetId: String(auth.user.id),
  })
  return { ok: true }
})
