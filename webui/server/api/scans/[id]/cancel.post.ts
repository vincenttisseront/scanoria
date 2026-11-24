// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/scans/:id/cancel (operator) : annule une analyse en file, déposée
// ou en cours ; 409 E_SCAN_STATE si elle est déjà terminée. Audité.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { auditScanAction, scanError, scanIdParam } from '../../../scans/api'
import { cancelScan } from '../../../scans/worker'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = scanIdParam(getRouterParam(event, 'id'))
  const pool = getPool()
  const exists = await pool.query('SELECT 1 FROM scans WHERE id = $1', [id])
  if (!exists.rowCount) throw scanError(404, 'E_SCAN_NOT_FOUND')
  const ok = await cancelScan(pool, id)
  await auditScanAction(event, auth, 'scan.cancel', id, ok ? 'success' : 'failure')
  if (!ok) throw scanError(409, 'E_SCAN_STATE')
  return { scan_id: id, status: 'cancelled' as const }
})
