// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/vigilance (lecteur) : vigilance de l'appliance (0.6, chantier B) —
// vulnérabilités de la console et des modules (F19) et alertes « mise à jour
// disponible », derniers canaris (G14), images retenues, essais (F13).

import { defineEventHandler } from 'h3'
import { requireAuth } from '../../utils/http'
import { getPool } from '../../utils/db'
import { loadCatalogContext } from '../../utils/catalog-view'
import { vigilanceSummary } from '../../vigilance/api'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  return vigilanceSummary(getPool(), await loadCatalogContext())
})
