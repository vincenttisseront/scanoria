// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/:id/discover (operator) : découverte immédiate des dépôts
// (sinon faite chaque heure par la planification).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { discoverForge } from '../../../projects/discover'
import { projectError } from '../../../projects/errors'
import { requireForge } from '../../../projects/guards'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const forge = await requireForge(pool, getRouterParam(event, 'id'))
  if (!forge.credential_id) throw projectError(409, 'E_NO_FORGE_ACCESS')
  return discoverForge(pool, forge, { userId: auth.user.id, username: auth.user.username })
})
