// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/owner-mappings {project_id|null, owner, user_id} (admin) : retire
// une correspondance responsable → compte (F6). Auditée.

import { defineEventHandler } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { ownerMappingSchema, removeOwnerMapping } from '../../findings/owners'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, ownerMappingSchema)
  const removed = await withTransaction(getPool(), async (db) => {
    const r = await removeOwnerMapping(db, body)
    if (r) {
      await writeAudit(db, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'owner-mapping.remove', outcome: 'success', targetType: 'user', targetId: String(body.user_id),
        details: { project_id: body.project_id, owner: body.owner },
      })
    }
    return r
  })
  if (!removed) throw apiError(404, 'E_NOT_FOUND')
  return { removed }
})
