// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/scans/:id/replay (operator) : rejouer à l'identique (G11) — même
// commit, même plan (modules, versions, empreintes, options, règles du gate).
// Un module du plan qui n'est plus disponible est constaté manquant, et
// l'analyse est alors non concluante (G13).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { enqueueFromApi, scanError, scanIdParam } from '../../../scans/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const id = scanIdParam(getRouterParam(event, 'id'))
  const r = await getPool().query<{ project_id: string, ref: string, commit_sha: string | null }>(
    'SELECT project_id, ref, commit_sha FROM scans WHERE id = $1', [id])
  const scan = r.rows[0]
  if (!scan) throw scanError(404, 'E_SCAN_NOT_FOUND')
  return enqueueFromApi(event, { projectId: scan.project_id, ref: scan.ref, commit: scan.commit_sha, trigger: 'replay', replayOf: id }, 'scan.replay', id)
})
