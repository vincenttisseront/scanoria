// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id/tokens (operator) : jetons d'API du projet (jamais la
// valeur ni l'empreinte : préfixe, dates, état).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { listApiTokens } from '../../../gates/tokens'
import { getProjectRef } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  const pool = getPool()
  if (!(await getProjectRef(pool, id))) throw apiError(404, 'E_NOT_FOUND')
  return { items: await listApiTokens(pool, id) }
})
