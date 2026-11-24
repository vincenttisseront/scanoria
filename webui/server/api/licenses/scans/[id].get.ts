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
  const auth = requireRole(event, 'viewer')
  const id = getRouterParam(event, 'id')
  if (!id || !UUID_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  // Comme la recherche transverse (F3) : un projet archivé n'est visible que d'un administrateur.
  const s = await pool.query(
    'SELECT 1 FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = $1 AND ($2::boolean OR p.archived_at IS NULL)',
    [id, auth.user.role === 'admin'])
  if (!s.rowCount) throw apiError(404, 'E_NOT_FOUND')
  const items = await scanLicenseDecisions(pool, id)
  const counts = { allowed: 0, review: 0, denied: 0 }
  for (const i of items) counts[i.decision]++
  return { counts, items }
})
