// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/output?kind=&subject_id=&locale= (viewer) : dernière sortie IA
// d'un résultat ou d'une analyse, marquée IA (modèle et empreinte), ou l'état
// de la tâche en cours. Rien n'est affiché à moitié : output null tant que la
// tâche n'est pas terminée.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { latestOutput, OutputQuery } from '../../ai/console'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const q = queryValidated(event, OutputQuery)
  const r = await latestOutput(getPool(), q, auth.user.locale, auth.user.id)
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return r
})
