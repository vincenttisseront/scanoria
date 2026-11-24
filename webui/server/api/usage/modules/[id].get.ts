// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/usage/modules/:id (lecteur) : consommation d'un module installé
// (F14), avec les courbes mémoire, CPU et disque sur 7 et 30 jours pour un
// module permanent.

import { defineEventHandler, getRouterParam } from 'h3'
import { MODULE_ID_RE } from '#shared/schemas'
import { getPool } from '../../../utils/db'
import { apiError, queryValidated, requireAuth } from '../../../utils/http'
import { loadCatalogContext } from '../../../utils/catalog-view'
import { moduleUsageDetail, usageQuery } from '../../../usage/stats'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const id = getRouterParam(event, 'id') ?? ''
  if (!MODULE_ID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const q = queryValidated(event, usageQuery)
  const detail = await moduleUsageDetail(getPool(), await loadCatalogContext(), id, q.unused_days)
  if (!detail) throw apiError(404, 'E_NOT_FOUND')
  return detail
})
