// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings/:id (viewer) : détail d'un résultat, analyses où il apparaît.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, requireRole } from '../../utils/http'
import { getFinding } from '../../findings/triage'
import { uuidParam } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  const row = id ? await getFinding(getPool(), id) : null
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  return row
})
