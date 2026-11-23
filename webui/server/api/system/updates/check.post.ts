// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/updates/check (admin) : demande check-update.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['check-update'])
  return submitHelperAction(event, 'check-update', params)
})
