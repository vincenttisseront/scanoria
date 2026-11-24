// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/licenses/scans/:id (viewer) : décision de licence de chaque
// composant du SBOM d'une analyse (colonne « licence » de l'onglet SBOM).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { scanLicenseDecisions } from '../../../licenses/policy'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = getRouterParam(event, 'id')
  if (!id || !UUID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const s = await pool.query('SELECT 1 FROM scans WHERE id = $1', [id])
  if (!s.rowCount) throw apiError(404, 'E_NOT_FOUND')
  const items = await scanLicenseDecisions(pool, id)
  const counts = { allowed: 0, review: 0, denied: 0 }
  for (const i of items) counts[i.decision]++
  return { counts, items }
})
