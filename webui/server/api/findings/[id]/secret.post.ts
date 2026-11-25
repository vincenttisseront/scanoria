// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/secret (operator) : suivi d'un secret (F7),
// « à révoquer » → « révoqué » ou « faux positif », avec date et auteur.
// La valeur du secret n'est jamais stockée ni renvoyée.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { getFinding, setSecretState, TriageError } from '../../../findings/triage'
import { triageHttpError } from '../../../findings/triage-http'
import { secretStateSchema, uuidParam } from '../../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, secretStateSchema)
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    await withTransaction(pool, async (db) => {
      const { before } = await setSecretState(db, id, body.state, auth.user.id)
      await writeAudit(db, {
        actor, action: 'finding.secret-state', outcome: 'success', targetType: 'finding', targetId: id,
        details: { project_id: before.project_id, from: before.secret_state, to: body.state },
      })
    })
  }
  catch (err) {
    if (err instanceof TriageError && err.code === 'E_NOT_FOUND') throw apiError(404, 'E_NOT_FOUND')
    throw await triageHttpError(err, pool, actor, id, { secret_state: body.state })
  }
  return getFinding(pool, id)
})
