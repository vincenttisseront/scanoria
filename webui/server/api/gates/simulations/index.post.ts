// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/gates/simulations (operator) : F9, simule des règles candidates
// sur l'historique d'un gate ou d'un projet (contrat 39), sans rien
// enregistrer d'autre que la simulation. Historique court : résultat immédiat
// (201, status « done ») ; long : 202 et status « pending », à suivre par
// GET /api/gates/simulations/:id. Enregistrer les règles reste PATCH
// /api/gates/:id, confirmé et audité.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, readValidated, requireRole } from '../../../utils/http'
import { SimulationError, simulationRequestSchema, sinceFromDays, startSimulation } from '../../../gates/simulate'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, simulationRequestSchema)
  try {
    const row = await startSimulation(getPool(), {
      gateId: body.gate_id ?? null, projectId: body.project_id ?? null, rules: body.rules,
      since: sinceFromDays(body.since_days), origin: 'manual', createdBy: auth.user.id,
    })
    setResponseStatus(event, row.status === 'pending' ? 202 : 201)
    return row
  }
  catch (err) {
    if (err instanceof SimulationError) throw apiError(err.code === 'E_NOT_FOUND' ? 404 : err.code === 'E_RATE_LIMITED' ? 429 : 400, err.code)
    throw err
  }
})
