// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/scans/:id/retry (operator) : relance — nouvelle analyse du même
// projet, de la même ref et du même profil, avec l'état actuel des modules.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { enqueueFromApi, scanError, scanIdParam } from '../../../scans/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const id = scanIdParam(getRouterParam(event, 'id'))
  const r = await getPool().query<{ project_id: string, ref: string, profile: string }>(
    'SELECT s.project_id, s.ref, p.slug AS profile FROM scans s JOIN profiles p ON p.id = s.profile_id WHERE s.id = $1', [id])
  const scan = r.rows[0]
  if (!scan) throw scanError(404, 'E_SCAN_NOT_FOUND')
  return enqueueFromApi(event, { projectId: scan.project_id, ref: scan.ref, trigger: 'manual', profileSlug: scan.profile }, 'scan.retry', id)
})
