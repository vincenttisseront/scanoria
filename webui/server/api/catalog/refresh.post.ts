// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/refresh (admin) : demande refresh-catalog (téléchargement
// et vérification de la signature de l'index par le helper).

import { defineEventHandler } from 'h3'
import { readValidated, requireRole } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const params = await readValidated(event, requestParamSchemas['refresh-catalog'])
  return submitHelperAction(event, 'refresh-catalog', params)
})
