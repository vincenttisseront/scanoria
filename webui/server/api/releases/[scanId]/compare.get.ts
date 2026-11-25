// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/releases/:scanId/compare?with=<analyse> (viewer) : F2 entre cette
// release et une autre analyse du même projet, choisie dans la page Release.
// Résultats introduits, corrigés et inchangés, par outil et par gravité.

import { defineEventHandler, getRouterParam } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { queryValidated, requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { compareScans } from '../../../release/compare'
import { releaseError } from '../../../release/api'

const Query = z.object({ with: z.uuid() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const scanId = uuidParam(getRouterParam(event, 'scanId'))
  const q = queryValidated(event, Query)
  const pool = getPool()
  const r = await pool.query<{ id: string }>(
    `SELECT b.id::text FROM scans a JOIN scans b ON b.project_id = a.project_id
      WHERE a.id = $1 AND b.id = $2 AND a.trigger = 'release'`, [scanId, q.with.toLowerCase()])
  if (!r.rows[0]) throw releaseError(404, 'E_RELEASE_NOT_FOUND')
  return compareScans(pool, q.with.toLowerCase(), scanId)
})
