// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/exceptions/:id (operator) : révoque une exception (ou retire une
// demande) ; elle cesse de s'appliquer aussitôt, l'historique est conservé.
// Auditée. 0.7 (B) : une exception approuvée révoquée redevient bloquante dans
// le verdict des dernières analyses (reevaluateProject, sans réanalyse).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { ExceptionError, reevaluateProject, revokeException } from '../../findings/exceptions'
import { uuidParam } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  let row
  try {
    row = await withTransaction(getPool(), async (db) => {
      const row = await revokeException(db, id, auth.user.id)
      await writeAudit(db, {
        actor, action: 'exception.revoke', outcome: 'success', targetType: 'exception', targetId: id,
        details: { project_id: row.project_id, kind: row.kind },
      })
      return row
    })
  }
  catch (err) {
    if (err instanceof ExceptionError) throw apiError(404, 'E_NOT_FOUND')
    throw err
  }
  if (row.status === 'approved') await reevaluateProject(getPool(), row.project_id)
  return row
})
