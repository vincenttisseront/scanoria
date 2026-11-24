// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/catalog/modules/:id (lecteur) : détail d'un module — versions,
// schéma des options (G3), état installé, plan d'installation, dépendances
// et modules qui en dépendent (G1), dernières opérations.

import { defineEventHandler, getRouterParam } from 'h3'
import { apiError, requireAuth } from '../../../../utils/http'
import { compatibility, loadCatalogContext, moduleSummary, updateAvailable } from '../../../../utils/catalog-view'
import { latestModules } from '../../../../utils/catalog'
import { dependentsOf } from '../../../../utils/module-plan'
import { MODULE_ID_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const id = getRouterParam(event, 'id') ?? ''
  if (!MODULE_ID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const ctx = await loadCatalogContext()
  const latest = latestModules(ctx.index).get(id)
  const installed = ctx.installed.find(m => m.id === id)
  if (!latest && !installed) throw apiError(404, 'E_NOT_FOUND')
  return {
    module: latest ? moduleSummary(latest) : null,
    options_schema: latest?.options ?? null,
    options_i18n: latest?.options_i18n ?? null,
    versions: (ctx.index?.modules ?? []).filter(m => m.id === id).map(m => m.version),
    installed: installed ?? null,
    update_available: updateAvailable(installed, latest),
    plan: latest && !installed ? compatibility(ctx, [id]) : null,
    dependents: dependentsOf(id, ctx),
    operations: ctx.operations.filter(o => o.module === id).slice(-10),
    dns: ctx.dns,
  }
})
