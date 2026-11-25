// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates/simulations/:id (viewer) : état et résultat d'une simulation
// de quality gate (F9, I19). result est null tant qu'elle n'est pas terminée.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { getSimulation } from '../../../gates/simulate'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const row = await getSimulation(getPool(), uuidParam(getRouterParam(event, 'id')))
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  return row
})
