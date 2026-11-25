// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/exceptions/:id/decision {decision, reason} (admin, session humaine
// seulement : aucun jeton d'API n'atteint cette route) : approuve ou refuse
// une demande (F5, J15). Refusée au demandeur, à un auteur du commit analysé,
// à un compte « agent » ou « bot ». Après une approbation, le verdict des
// dernières analyses du projet est recalculé sans réanalyse (reevaluateProject),
// puis les écouteurs onVerdictChanged republient les statuts de forge.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { auditDecisionDenied, decideException, decisionSchema, ExceptionError, reevaluateProject } from '../../../findings/exceptions'
import { exceptionHttpError } from '../../../findings/exceptions-http'
import { uuidParam } from '../../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  // Une décision n'est jamais prise par un jeton de CI (défense en profondeur).
  if (event.context.apiToken) throw apiError(403, 'E_DECIDER_NOT_ALLOWED', { reason: 'not-human' })
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, decisionSchema)
  const pool = getPool()
  const ip = clientAddress(event)
  let row
  try {
    row = await withTransaction(pool, db => decideException(db, id, { ...body, deciderUserId: auth.user.id, ip }))
  }
  catch (err) {
    if (err instanceof ExceptionError && err.code !== 'E_NOT_FOUND' && err.code !== 'E_VALIDATION') {
      await auditDecisionDenied(pool, id, { type: 'user', userId: auth.user.id, username: auth.user.username, ip }, err)
    }
    throw exceptionHttpError(err)
  }
  const reevaluated = row.status === 'approved' ? await reevaluateProject(pool, row.project_id) : []
  return { ...row, reevaluated }
})
