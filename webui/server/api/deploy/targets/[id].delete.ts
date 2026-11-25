// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/deploy/targets/:id (admin) : retire une cible et son jeton ;
// l'historique de ses exécutions part avec elle (confirmé dans une modale).

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../utils/http'
import { deleteTarget, getTarget } from '../../../deploy/targets'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const target = await getTarget(pool, getRouterParam(event, 'id') ?? '')
  if (!target) throw apiError(404, 'E_NOT_FOUND')
  await deleteTarget(pool, target, { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) })
  setResponseStatus(event, 204)
  return null
})
