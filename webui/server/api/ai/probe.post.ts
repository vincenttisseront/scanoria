// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/probe (admin) : relance la découverte des modèles (scanoria-ai).

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, requireRole } from '../../utils/http'
import { requestProbe } from '../../ai/console'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  if (!(await requestProbe(getPool()))) throw apiError(409, 'E_UNAVAILABLE')
  setResponseStatus(event, 202)
  return { queued: true }
})
