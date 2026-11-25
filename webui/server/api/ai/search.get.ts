// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/search?subject_id= (viewer) : état de la traduction (I8) et,
// une fois terminée, les filtres résolus pour cette personne (projets visibles
// seulement), à afficher et modifier avant de les appliquer. Rien n'est exécuté.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { readSearch, SearchQuery } from '../../ai/search'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const q = queryValidated(event, SearchQuery)
  const r = await readSearch(getPool(), q, auth.user.role, auth.user.locale)
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return r
})
