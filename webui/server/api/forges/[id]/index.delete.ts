// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/forges/:id (admin) : retire une forge et son jeton. Refusé
// (409 E_FORGE_IN_USE) tant que des projets en dépendent.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { clientAddress, requireRole } from '../../../utils/http'
import { deleteForge } from '../../../projects/forges'
import { requireForge } from '../../../projects/guards'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const forge = await requireForge(pool, getRouterParam(event, 'id'))
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  await deleteForge(pool, forge, actor)
  return { deleted: true }
})
