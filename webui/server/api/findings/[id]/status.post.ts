// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/status (operator) : tri d'un résultat. Chaque
// changement est audité, chaque refus aussi.
// - « accepted » (motif et date de fin) ne pose PAS le statut : il dépose une
//   demande d'exception de type « finding » (F5, J15), que seul un
//   administrateur approuve ; l'approbation pose alors le statut. Réponse 202
//   avec le résultat inchangé et la demande (exception_request).
// - « false-positive » est refusé (403 E_TRIAGE_NOT_ALLOWED) à un compte non
//   humain et à l'auteur du commit concerné, comme une approbation J15.
// - Un résultat malveillant (H4) ne peut être ni accepté ni classé faux positif.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { getFinding, setFindingStatus } from '../../../findings/triage'
import { isoDay, MAX_EXCEPTION_DAYS, requestFindingAcceptance } from '../../../findings/exceptions'
import { triageHttpError } from '../../../findings/triage-http'
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
    if (body.status === 'accepted') {
      const { request } = await withTransaction(pool, db =>
        requestFindingAcceptance(db, id, auth.user, { reason: body.reason, until: body.until }))
      setResponseStatus(event, 202)
      return { ...(await getFinding(pool, id)), exception_request: request }
    }
    await withTransaction(pool, async (db) => {
      const { before } = await setFindingStatus(db, id, { status: body.status, reason: body.reason ?? null }, auth.user.id)
      await writeAudit(db, {
        actor, action: 'finding.status', outcome: 'success', targetType: 'finding', targetId: id,
        details: { project_id: before.project_id, from: before.status, to: body.status, reason: body.reason ?? null },
      })
    })
  }
  catch (err) {
    throw await triageHttpError(err, pool, actor, id, { to: body.status })
  }
  return getFinding(pool, id)
})
