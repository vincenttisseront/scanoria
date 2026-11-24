// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/similar?finding_id= (viewer) : résultats semblables (I7) du même
// projet, calculés par scanoria-ai à partir des embeddings, avec l'état de la
// fonction (sans modèle d'embedding, banc d'essai en cours ou échoué…). Une
// suggestion seulement : le tri commun passe par POST /api/findings/:id/status,
// un résultat à la fois, avec son audit.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { SimilarQuery, similarFindings } from '../../ai/console-05'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const r = await similarFindings(getPool(), queryValidated(event, SimilarQuery).finding_id)
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return r
})
