// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates/:id (viewer) : règles, projets affectés, champs verrouillés (H4, G13).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireAuth } from '../../../utils/http'
import { gateProjects, getGate } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const id = uuidParam(getRouterParam(event, 'id'))
  const pool = getPool()
  const gate = await getGate(pool, id)
  if (!gate) throw apiError(404, 'E_NOT_FOUND')
  return {
    ...gate,
    project_list: await gateProjects(pool, id),
    locked: { block_malicious: 'H4', inconclusive_blocks: 'G13' },
  }
})
