// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/ci/protection (admin, personne seulement : aucun
// jeton de CI n'atteint cette route) {request_id, action, include_release_gate?,
// confirm: true} : applique par l'API de la forge, ou refuse, la règle de
// protection proposée (J2). La modale montre la règle exacte avant l'envoi.
// Une nouvelle proposition : protection-request.post.ts.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { IntegrationError, decideProtection } from '../../../../ci/integration'
import { protectionDecisionSchema } from '../../../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, protectionDecisionSchema)
  try {
    return await decideProtection(getPool(), id, body.request_id, {
      action: body.action, includeReleaseGate: body.include_release_gate, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event),
    })
  }
  catch (err) {
    if (err instanceof IntegrationError) {
      if (err.code === 'E_INTEGRATION_NOT_FOUND') throw apiError(404, 'E_NOT_FOUND')
      throw apiError(409, 'E_INTEGRATION_STATE')
    }
    throw err
  }
})
