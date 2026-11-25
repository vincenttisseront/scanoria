// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/owner-mappings {project_id|null, owner, user_id} (admin) : relie un
// responsable CODEOWNERS à un compte (F6), pour tous les projets ou un seul.
// DELETE /api/owner-mappings (même corps) la retire. Auditées.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { addOwnerMapping, ownerMappingSchema } from '../../findings/owners'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, ownerMappingSchema)
  const pool = getPool()
  const ok = await withTransaction(pool, async (db) => {
    const u = await db.query('SELECT 1 FROM users WHERE id = $1', [body.user_id])
    if (!u.rowCount) return null
    if (body.project_id && !(await db.query('SELECT 1 FROM projects WHERE id = $1', [body.project_id])).rowCount) return null
    const added = await addOwnerMapping(db, body)
    if (added) {
      await writeAudit(db, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'owner-mapping.add', outcome: 'success', targetType: 'user', targetId: String(body.user_id),
        details: { project_id: body.project_id, owner: body.owner },
      })
    }
    return added
  })
  if (ok === null) throw apiError(404, 'E_NOT_FOUND')
  setResponseStatus(event, ok ? 201 : 200)
  return { added: ok }
})
