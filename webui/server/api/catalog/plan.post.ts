// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/plan (lecteur) : plan d'installation sans effet — modules
// ajoutés automatiquement et pourquoi, licences à accepter, ressources.

import { defineEventHandler } from 'h3'
import { apiError, readValidated, requireAuth } from '../../utils/http'
import { loadCatalogContext } from '../../utils/catalog-view'
import { planRequests } from '../../utils/catalog-actions'
import { buildInstallPlan } from '../../utils/module-plan'
import { planBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const body = await readValidated(event, planBodySchema)
  const ctx = await loadCatalogContext()
  if (!ctx.index) throw apiError(503, 'E_CATALOG_UNAVAILABLE')
  return buildInstallPlan(planRequests(body, ctx), ctx)
})
