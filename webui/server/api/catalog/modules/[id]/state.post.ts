// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/state (admin) : demande set-module-state.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { moduleStateBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, ctx } = await installedModuleParam(event)
  const body = await readValidated(event, moduleStateBodySchema)
  return submitHelperAction(event, 'set-module-state', { id, enabled: body.enabled }, {
    auditDetails: { dependents: body.enabled ? [] : ctx.dependents },
  })
})
