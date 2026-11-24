// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans (viewer) : file active (status=active, dans l'ordre du worker)
// ou historique filtrable (projet, état, verdict, déclencheur), paginé.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listScans, scanListQuery } from '../../scans/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return listScans(getPool(), queryValidated(event, scanListQuery))
})
