// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/agent-inventory (viewer) : inventaire des workflows
// d'agents relevé par le module agentic-radar (K7, 0.7) pour cette analyse,
// ou { inventory: null } s'il n'y en a pas.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { readAgentInventory } from '../../../ai/agent-inventory'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  return { inventory: await readAgentInventory(getPool(), id) }
})
