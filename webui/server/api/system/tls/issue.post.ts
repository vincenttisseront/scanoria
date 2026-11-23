// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/tls/issue (admin) : demande issue-certificate (certificat
// interne <nom> / *.<nom>, retour au mode interne).

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['issue-certificate'])
  return submitHelperAction(event, 'issue-certificate', params)
})
