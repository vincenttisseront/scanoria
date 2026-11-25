// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/gates/projects/:id/suggestion/simulate (operator) : I19, passe la
// dernière proposition de seuils de l'IA dans le simulateur F9 (origin
// « ai »), ou rend la simulation déjà faite pour elle. Les règles viennent de
// la sortie IA enregistrée, jamais du corps de la requête. 404 sans
// proposition (connecteur coupé, projet « aucun envoi à l'IA », pas encore
// calculée).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../../utils/db'
import { apiError, requireRole } from '../../../../../utils/http'
import { uuidParam } from '../../../../../gates/http'
import { simulateSuggestion } from '../../../../../gates/suggest'
import { SimulationError } from '../../../../../gates/simulate'

export default defineEventHandler(async (event) => {
  // Comme POST /api/gates/simulations : lancer un rejeu demande le rôle operator.
  const auth = requireRole(event, 'operator')
  let r: Awaited<ReturnType<typeof simulateSuggestion>>
  try {
    r = await simulateSuggestion(getPool(), uuidParam(getRouterParam(event, 'id')), auth.user.id)
  }
  catch (err) {
    if (err instanceof SimulationError) throw apiError(err.code === 'E_RATE_LIMITED' ? 429 : err.code === 'E_NOT_FOUND' ? 404 : 400, err.code)
    throw err
  }
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return {
    task_id: r.suggestion.task_id,
    gate_id: r.suggestion.gate_id,
    gate_slug: r.suggestion.gate_slug,
    rules: r.suggestion.rules,
    simulation: r.simulation,
  }
})
