// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/hostname (admin) : demande set-hostname. Le service root
// crée une nouvelle AC interne (contrainte de nom) : les postes la réimportent.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['set-hostname'])
  return submitHelperAction(event, 'set-hostname', params)
})
