// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/install (admin) : calcule le plan (dépendances ajoutées,
// défauts des options), le refuse s'il est bloqué (409 E_PLAN), sinon dépose
// install-modules. Les licences à restriction doivent être acceptées.

import { defineEventHandler } from 'h3'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { loadCatalogContext } from '../../utils/catalog-view'
import { planRequests } from '../../utils/catalog-actions'
import { buildInstallPlan } from '../../utils/module-plan'
import { installBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const body = await readValidated(event, installBodySchema)
  const ctx = await loadCatalogContext()
  if (!ctx.index) throw apiError(503, 'E_CATALOG_UNAVAILABLE')
  const plan = buildInstallPlan(planRequests(body, ctx), { ...ctx, acceptLicenses: body.accept_licenses })
  if (!plan.ok) throw apiError(409, 'E_PLAN', { blockers: plan.blockers })
  const params = {
    modules: plan.items.map(i => ({ id: i.id, version: i.version, options: i.options })),
    accept_licenses: plan.licenses_to_accept,
  }
  return submitHelperAction(event, 'install-modules', params, {
    dbContext: { pack: body.pack ?? null },
    auditDetails: {
      pack: body.pack ?? null,
      requested: plan.items.filter(i => i.reason === 'requested').map(i => i.id),
      auto_added: plan.items.filter(i => i.reason !== 'requested').map(i => ({ id: i.id, reason: i.reason, required_by: i.required_by })),
      licenses_accepted: plan.licenses_to_accept,
    },
  })
})
