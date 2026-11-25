// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/export (admin) : exporte un lot hors ligne signé
// des modules choisis (bases et catalogue suivent, G1), ou l'estime seulement
// (dry_run : taille annoncée avant de lancer l'export).

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

const body = requestParamSchemas['export-bundle'].options[0]

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const params = await readValidated(event, body)
  const res = await submitHelperAction(event, 'export-bundle', params, { auditDetails: { modules: params.modules, dry_run: !!params.dry_run } })
  if (!params.dry_run) {
    await getPool().query(
      `INSERT INTO offline_bundles (direction, status, contents, request_id, requested_by)
       VALUES ('export', 'queued', $1::jsonb, $2, $3)`,
      [JSON.stringify({ modules: params.modules }), res.request_id, auth.user.id])
  }
  return res
})
