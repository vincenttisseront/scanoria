// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/licenses/policy (admin) : décision d'une licence, globale ou pour
// un projet (F8). Crée ou remplace ; tracée dans l'audit avec l'ancienne valeur.

import { defineEventHandler } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { PolicyError, policyUpsertSchema, upsertPolicy } from '../../../licenses/policy'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, policyUpsertSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    return await withTransaction(getPool(), async (db) => {
      const { row, previous } = await upsertPolicy(db, body, auth.user.id)
      await writeAudit(db, {
        actor, action: 'license-policy.set', outcome: 'success', targetType: 'license-policy', targetId: row.id,
        details: { project_id: body.project_id, license: body.license, decision: body.decision, previous, reason: body.reason ?? null },
      })
      return row
    })
  }
  catch (err) {
    if (err instanceof PolicyError) throw apiError(404, 'E_NOT_FOUND')
    throw err
  }
})
