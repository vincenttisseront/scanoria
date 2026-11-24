// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/forges/:id (admin) : nom, découverte, jeton (vérifié avant
// d'être enregistré ; null le retire).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { updateForge } from '../../../projects/forges'
import { requireForge } from '../../../projects/guards'
import { forgeUpdateSchema } from '../../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const forge = await requireForge(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, forgeUpdateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return { forge: await updateForge(pool, forge, body, actor) }
})
