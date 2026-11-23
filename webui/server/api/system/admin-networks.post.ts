// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/admin-networks (admin) : demande set-admin-networks.
// L'adresse cliente est jointe (anti-verrouillage contrôlé par le service root).

import { defineEventHandler } from 'h3'
import { readValidated } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['set-admin-networks'])
  return submitHelperAction(event, 'set-admin-networks', params)
})
