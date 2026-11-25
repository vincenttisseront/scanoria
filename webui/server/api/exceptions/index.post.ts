// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/exceptions (operator) : DEMANDE d'exception motivée et datée (au
// plus un an), soumise à l'approbation d'un autre administrateur (F5, J15).
// Elle ne compte pour le gate qu'une fois approuvée. Refusée pour un avis MAL-
// ou un résultat malveillant (H4) et contre un verrou de profil (G8).
// Auditée (exception.request, ou refus).

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { exceptionCreateSchema, ExceptionError, requestException } from '../../findings/exceptions'
import { exceptionHttpError } from '../../findings/exceptions-http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, exceptionCreateSchema)
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    const row = await withTransaction(pool, db => requestException(db, {
      ...body,
      requested_via: 'console',
      requester_label: auth.user.username,
      requester_is_human: true,
      requester_user_id: auth.user.id,
      commit_authors: [],
    }))
    setResponseStatus(event, 201)
    return row
  }
  catch (err) {
    if (err instanceof ExceptionError && (err.code === 'E_MALICIOUS' || err.code === 'E_LOCKED')) {
      await writeAudit(pool, { actor, action: 'exception.request', outcome: 'denied', targetType: 'project', targetId: body.project_id, details: { kind: body.kind, reason_code: err.code === 'E_MALICIOUS' ? 'malicious' : `locked:${err.detail}` } })
    }
    throw exceptionHttpError(err)
  }
})
