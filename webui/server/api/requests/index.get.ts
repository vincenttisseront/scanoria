// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/requests (operator et admin) : dernières demandes au service root.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { listHelperRequests } from '../../utils/requests'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  return { items: await listHelperRequests(getPool(), 50) }
})
