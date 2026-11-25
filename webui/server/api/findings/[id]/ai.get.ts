// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings/:id/ai (viewer) : origine d'un résultat d'un module
// d'analyse par IA (0.7, contrat 32) : confirmé ou non (hors verdict tant
// qu'il ne l'est pas), par qui et quand, modèle et début de son empreinte.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { AiFindingError, getAiFinding } from '../../../findings/ai-findings'
import { uuidParam } from '../../../findings/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  try {
    return await getAiFinding(getPool(), id)
  }
  catch (err) {
    if (err instanceof AiFindingError) throw apiError(404, 'E_NOT_FOUND')
    throw err
  }
})
