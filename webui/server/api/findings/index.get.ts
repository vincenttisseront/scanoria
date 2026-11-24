// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings (viewer) : résultats unifiés, filtrés et paginés côté serveur.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listFindings } from '../../findings/triage'
import { findingQuerySchema } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, findingQuerySchema)
  return listFindings(getPool(), q)
})
