// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/selftest (admin) : demande run-selftest.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['run-selftest'])
  return submitHelperAction(event, 'run-selftest', params)
})
