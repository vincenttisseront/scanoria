// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/schedule (admin) : export périodique d'un lot
// (désactivé par défaut ; hebdomadaire, 2 lots gardés quand il est activé).

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

const body = requestParamSchemas['export-bundle'].options[1]

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, body)
  return submitHelperAction(event, 'export-bundle', params, { auditDetails: { schedule: params.schedule } })
})
