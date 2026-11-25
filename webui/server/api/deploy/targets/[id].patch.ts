// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/deploy/targets/:id (admin) : activation, configuration, jeton et,
// pour une cible GitOps seulement, fusion automatique de la forge autorisée
// par cet administrateur (auto_merge_by, J12).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { getTarget, updateTarget } from '../../../deploy/targets'
import { targetUpdateSchema } from '../../../deploy/config'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const target = await getTarget(pool, getRouterParam(event, 'id') ?? '')
  if (!target) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, targetUpdateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return { target: await updateTarget(pool, target, body, actor) }
})
