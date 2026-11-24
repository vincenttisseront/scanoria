// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/usage/modules (lecteur) : consommation réelle de chaque module
// installé (F14) et modules inutilisés depuis N jours (30 par défaut).

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { queryValidated, requireAuth } from '../../../utils/http'
import { loadCatalogContext } from '../../../utils/catalog-view'
import { listModulesUsage, usageQuery } from '../../../usage/stats'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const q = queryValidated(event, usageQuery)
  return listModulesUsage(getPool(), await loadCatalogContext(), q.unused_days)
})
