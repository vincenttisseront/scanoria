// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/audit (operator et admin) : journal d'audit paginé et filtrable.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listAudit } from '../../utils/audit'
import { auditQuerySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const q = queryValidated(event, auditQuerySchema)
  return listAudit(getPool(), q)
})
