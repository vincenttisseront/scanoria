// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/suggestions?kind=triage-finding|classify-secret&ids=… (viewer) :
// dernier indice IA de chaque résultat demandé (I3 pré-tri, I14 type de
// secret), pour l'afficher à côté du statut dans la liste. Lecture seule :
// aucune suggestion ne change un statut.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { latestSuggestions, SuggestionsQuery } from '../../ai/console'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return latestSuggestions(getPool(), queryValidated(event, SuggestionsQuery))
})
