// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/users (admin) : crée un compte local ; le mot de passe initial
// doit être changé à la première connexion.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { UsernameTakenError, createUser } from '../../utils/users'
import { userCreateSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, userCreateSchema)
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    const user = await createUser(pool, {
      username: body.username,
      displayName: body.display_name ?? null,
      email: body.email ?? null,
      role: body.role,
      locale: body.locale,
      password: body.password,
      mustChangePassword: true,
    })
    await writeAudit(pool, {
      actor, action: 'user.create', outcome: 'success', targetType: 'user', targetId: user.id,
      details: { username: user.username, role: user.role },
    })
    setResponseStatus(event, 201)
    return user
  }
  catch (err) {
    if (err instanceof UsernameTakenError) throw apiError(409, 'E_USERNAME_TAKEN')
    throw err
  }
})
