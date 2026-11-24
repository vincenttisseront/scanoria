// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/exceptions (operator) : exception motivée et datée (au plus un
// an). Refusée pour un avis MAL- ou un résultat malveillant (H4). Auditée.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { createException, exceptionCreateSchema, ExceptionError } from '../../findings/exceptions'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, exceptionCreateSchema)
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    const row = await withTransaction(pool, async (db) => {
      const created = await createException(db, body, auth.user.id)
      await writeAudit(db, {
        actor, action: 'exception.create', outcome: 'success', targetType: 'exception', targetId: created.id,
        details: { project_id: body.project_id, kind: body.kind, target: body.target, reason: body.reason, expires_on: body.expires_on },
      })
      return created
    })
    setResponseStatus(event, 201)
    return row
  }
  catch (err) {
    if (err instanceof ExceptionError) {
      if (err.code === 'E_MALICIOUS') {
        await writeAudit(pool, { actor, action: 'exception.create', outcome: 'denied', targetType: 'project', targetId: body.project_id, details: { kind: body.kind, reason_code: 'malicious' } })
        throw apiError(409, 'E_MALICIOUS')
      }
      if (err.code === 'E_NOT_FOUND') throw apiError(404, 'E_NOT_FOUND')
      throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'expires_on', code: 'out_of_range' }] })
    }
    throw err
  }
})
