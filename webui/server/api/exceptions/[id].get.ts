// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/exceptions/:id (viewer) : une exception ou une demande, avec son
// circuit (demandeur, voie, auteurs exclus, décision).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, requireRole } from '../../utils/http'
import { getException } from '../../findings/exceptions'
import { uuidParam } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  const row = id ? await getException(getPool(), id) : null
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  return row
})
