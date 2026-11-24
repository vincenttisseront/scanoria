// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/exceptions?project_id=…[&all=true] (viewer) : exceptions d'un
// projet ; actives seulement par défaut (non révoquées, non échues).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listExceptions } from '../../findings/exceptions'
import { exceptionQuerySchema } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, exceptionQuerySchema)
  return { items: await listExceptions(getPool(), q.project_id, q.all ?? false) }
})
