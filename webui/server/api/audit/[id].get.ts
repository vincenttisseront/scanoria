// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/audit/:id (operator et admin) : détail d'une entrée du journal.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, idParam, requireRole } from '../../utils/http'
import { getAudit } from '../../utils/audit'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const id = idParam(getRouterParam(event, 'id'))
  const row = await getAudit(getPool(), String(id))
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  return row
})
