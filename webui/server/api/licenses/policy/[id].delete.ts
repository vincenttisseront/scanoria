// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/licenses/policy/:id (admin) : retire une décision ; la licence
// retombe sur le niveau inférieur (global, puis défaut). Tracé dans l'audit.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { deletePolicy, PolicyError } from '../../../licenses/policy'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = getRouterParam(event, 'id')
  if (!id || !UUID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    return await withTransaction(getPool(), async (db) => {
      const row = await deletePolicy(db, id)
      await writeAudit(db, {
        actor, action: 'license-policy.delete', outcome: 'success', targetType: 'license-policy', targetId: id,
        details: { project_id: row.project_id, license: row.license, previous: row.decision },
      })
      return { ok: true }
    })
  }
  catch (err) {
    if (err instanceof PolicyError) throw apiError(404, 'E_NOT_FOUND')
    throw err
  }
})
