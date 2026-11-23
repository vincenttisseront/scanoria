// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/users/:id/password (admin) : nouveau mot de passe, à changer à la
// prochaine connexion par défaut ; sessions du compte révoquées.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, idParam, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { getUser, setUserPassword } from '../../../utils/users'
import { revokeUserSessions } from '../../../utils/sessions'
import { userPasswordResetSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = idParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, userPasswordResetSchema)
  const pool = getPool()
  const user = await getUser(pool, id)
  if (!user) throw apiError(404, 'E_NOT_FOUND')
  const mustChange = body.must_change_password ?? true
  await setUserPassword(pool, id, body.password, mustChange)
  await revokeUserSessions(pool, id, id === auth.user.id ? auth.tokenHash : undefined)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'user.password-reset', outcome: 'success', targetType: 'user', targetId: String(id),
    details: { username: user.username, must_change_password: mustChange },
  })
  return { ok: true }
})
