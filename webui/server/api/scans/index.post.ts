// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/scans (operator) : analyse manuelle d'un projet {project_id, ref?,
// profile?}. Sans ref : branche par défaut du projet. 202 {scan_id, number,
// merged} ; 200 si une demande identique était déjà en file (fusionnée).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { readValidated, requireRole } from '../../utils/http'
import { enqueueFromApi, scanCreateBody, scanError } from '../../scans/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const body = await readValidated(event, scanCreateBody)
  let ref = body.ref
  if (!ref) {
    const r = await getPool().query<{ default_branch: string | null }>('SELECT default_branch FROM projects WHERE id = $1', [body.project_id])
    if (!r.rows[0]) throw scanError(404, 'E_SCAN_PROJECT_NOT_FOUND')
    ref = r.rows[0].default_branch ?? 'main'
  }
  return enqueueFromApi(event, { projectId: body.project_id, ref, trigger: 'manual', profileSlug: body.profile ?? null }, 'scan.create')
})
