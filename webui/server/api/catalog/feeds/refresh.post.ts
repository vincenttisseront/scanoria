// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/feeds/refresh (admin) : demande refresh-feeds. Le helper
// télécharge les bases des feeds installés (ou de ceux de ids) ; une base qui
// échoue garde la précédente. Le timer quotidien passe par la même action.

import { defineEventHandler } from 'h3'
import { readValidated, requireRole } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const params = await readValidated(event, requestParamSchemas['refresh-feeds'])
  return submitHelperAction(event, 'refresh-feeds', params)
})
