// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/projects/:id/tokens/:token (operator) : révoque un jeton (effet
// immédiat, la ligne reste pour l'historique). Audit api-token.revoke.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { getApiToken, revokeApiToken } from '../../../../gates/tokens'
import { uuidParam } from '../../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const id = uuidParam(getRouterParam(event, 'token'))
  const pool = getPool()
  const row = await getApiToken(pool, projectId, id)
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  const revoked = await revokeApiToken(pool, projectId, id)
  if (revoked) {
    await writeAudit(pool, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'api-token.revoke', outcome: 'success', targetType: 'api-token', targetId: id,
      details: { name: row.name, prefix: row.prefix },
    })
  }
  return getApiToken(pool, projectId, id)
})
