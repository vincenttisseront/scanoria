// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/updates/policy (admin) : demande set-update-policy (canal,
// recherche quotidienne, installation planifiée dans une fenêtre de maintenance).

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['set-update-policy'])
  return submitHelperAction(event, 'set-update-policy', params)
})
