// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates (viewer) : quality gates, nombre de projets affectés.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireAuth } from '../../utils/http'
import { listGates } from '../../gates/gates'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  return { items: await listGates(getPool()) }
})
