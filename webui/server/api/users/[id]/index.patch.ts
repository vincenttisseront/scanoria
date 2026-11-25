// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/users/:id (admin) : rôle, état, nom affiché, courriel, langue.
// Le dernier administrateur actif ne peut être ni rétrogradé ni désactivé.
// Un changement de rôle ou une désactivation révoque les sessions du compte.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, idParam, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { countActiveAdmins, getUser, updateUser } from '../../../utils/users'
import { revokeUserSessions } from '../../../utils/sessions'
import { userUpdateSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = idParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, userUpdateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return withTransaction(getPool(), async (client) => {
    await client.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE')
    const before = await getUser(client, id)
    if (!before) throw apiError(404, 'E_NOT_FOUND')
    const losesAdmin = before.role === 'admin' && before.is_active
      && ((body.role !== undefined && body.role !== 'admin') || body.is_active === false)
    if (losesAdmin && (await countActiveAdmins(client, id)) === 0) throw apiError(409, 'E_LAST_ADMIN')
    if (id === auth.user.id && body.is_active === false) throw apiError(409, 'E_SELF')
    // J15 (0.7) : un compte ne change pas sa propre nature (un « agent » ne se déclare pas humain).
    if (id === auth.user.id && body.kind !== undefined && body.kind !== before.kind) throw apiError(409, 'E_SELF')
    const after = await updateUser(client, id, body)
    const roleChanged = body.role !== undefined && body.role !== before.role
    if (roleChanged || body.is_active === false) await revokeUserSessions(client, id)
    const changes: Record<string, { from: unknown, to: unknown }> = {}
    for (const key of Object.keys(body) as (keyof typeof body)[]) {
      if (before[key] !== after?.[key]) changes[key] = { from: before[key], to: after?.[key] }
    }
    await writeAudit(client, {
      actor, action: 'user.update', outcome: 'success', targetType: 'user', targetId: String(id),
      details: { username: before.username, changes },
    })
    return after
  })
})
