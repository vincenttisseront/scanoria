// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/users/:id (admin) : supprime un compte (jamais le sien, jamais
// le dernier administrateur actif). Le journal d'audit garde le nom figé.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, idParam, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { countActiveAdmins, deleteUser, getUser } from '../../../utils/users'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = idParam(getRouterParam(event, 'id'))
  if (id === auth.user.id) throw apiError(409, 'E_SELF')
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return withTransaction(getPool(), async (client) => {
    await client.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE')
    const user = await getUser(client, id)
    if (!user) throw apiError(404, 'E_NOT_FOUND')
    if (user.role === 'admin' && user.is_active && (await countActiveAdmins(client, id)) === 0) {
      throw apiError(409, 'E_LAST_ADMIN')
    }
    await deleteUser(client, id)
    await writeAudit(client, {
      actor, action: 'user.delete', outcome: 'success', targetType: 'user', targetId: String(id),
      details: { username: user.username, role: user.role },
    })
    return { ok: true }
  })
})
