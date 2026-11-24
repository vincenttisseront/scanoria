// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/catalog (lecteur) : modules de l'index vérifié, état installé,
// compatibilité avec la machine, packs, graphe des dépendances, sélection
// conseillée et opérations en cours.

import { defineEventHandler } from 'h3'
import { requireAuth } from '../../utils/http'
import { buildCatalogView, loadCatalogContext } from '../../utils/catalog-view'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  return buildCatalogView(await loadCatalogContext())
})
