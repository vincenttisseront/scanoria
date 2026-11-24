// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id (viewer) : état, plan figé (G11), modules (état, durée,
// journal), couverture (G15), position dans la file et verdict brut.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { getScan, scanError, scanIdParam } from '../../../scans/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const scan = await getScan(getPool(), scanIdParam(getRouterParam(event, 'id')))
  if (!scan) throw scanError(404, 'E_SCAN_NOT_FOUND')
  return scan
})
