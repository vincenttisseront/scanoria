// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/ci/protection-request (operator) : propose (de
// nouveau) la règle de protection, sans rien appliquer. L'application reste
// la décision d'un administrateur (protection.post.ts).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, requireRole } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { requestProtection } from '../../../../ci/integration'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  const requestId = await requestProtection(getPool(), id)
  if (!requestId) throw apiError(404, 'E_NOT_FOUND')
  return { request_id: requestId }
})
