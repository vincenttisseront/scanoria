// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/uninstall (admin) : demande uninstall-module.
// Refusé (409 E_DEPENDENTS) si un module installé en dépend (G1).

import { defineEventHandler } from 'h3'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { moduleUninstallBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, installed, ctx } = await installedModuleParam(event)
  const body = await readValidated(event, moduleUninstallBodySchema)
  if (ctx.dependents.length) throw apiError(409, 'E_DEPENDENTS', { dependents: ctx.dependents })
  return submitHelperAction(event, 'uninstall-module', { id, keep_data: body.keep_data }, {
    auditDetails: { version: installed.version },
  })
})
