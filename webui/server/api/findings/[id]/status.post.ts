// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/status (operator) : tri d'un résultat. Accepté :
// motif et date de fin obligatoires. Un résultat malveillant (H4) ne peut
// être ni accepté ni classé faux positif. Chaque changement est audité.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { getFinding, setFindingStatus, TriageError } from '../../../findings/triage'
import { isoDay, MAX_EXCEPTION_DAYS } from '../../../findings/exceptions'
import { statusChangeSchema, uuidParam } from '../../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, statusChangeSchema)
  if (body.status === 'accepted' && (body.until < isoDay() || body.until > isoDay(MAX_EXCEPTION_DAYS))) {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'until', code: 'out_of_range' }] })
  }
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    await withTransaction(pool, async (db) => {
      const { before } = await setFindingStatus(db, id, {
        status: body.status,
        reason: body.reason ?? null,
        until: body.status === 'accepted' ? body.until : null,
      }, auth.user.id)
      await writeAudit(db, {
        actor, action: 'finding.status', outcome: 'success', targetType: 'finding', targetId: id,
        details: { project_id: before.project_id, from: before.status, to: body.status, reason: body.reason ?? null, until: body.status === 'accepted' ? body.until : null },
      })
    })
  }
  catch (err) {
    if (err instanceof TriageError) {
      if (err.code === 'E_MALICIOUS') {
        await writeAudit(pool, { actor, action: 'finding.status', outcome: 'denied', targetType: 'finding', targetId: id, details: { to: body.status, reason_code: 'malicious' } })
        throw apiError(409, 'E_MALICIOUS')
      }
      throw apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code === 'E_NOT_FOUND' ? 'E_NOT_FOUND' : 'E_VALIDATION')
    }
    throw err
  }
  return getFinding(pool, id)
})
