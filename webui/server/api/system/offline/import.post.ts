// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/import (admin) : importe le lot téléversé. Le
// helper vérifie tout (signature par une clé de confiance, index officiel,
// empreintes) ; aucun module n'est installé par l'import.

import { lstat } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler } from 'h3'
import { getConfig } from '../../../utils/config'
import { getPool } from '../../../utils/db'
import { apiError, readValidated, requireRole } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'
import { BUNDLE_UPLOAD_NAME } from '../../../offline/upload'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const params = await readValidated(event, requestParamSchemas['import-bundle'])
  try {
    const st = await lstat(join(getConfig().uploadsDir, params.upload_id, BUNDLE_UPLOAD_NAME))
    if (!st.isFile() || st.size === 0) throw new Error('not a file')
  }
  catch {
    throw apiError(400, 'E_UPLOAD')
  }
  const res = await submitHelperAction(event, 'import-bundle', params)
  await getPool().query(
    `INSERT INTO offline_bundles (direction, status, request_id, requested_by) VALUES ('import', 'queued', $1, $2)`,
    [res.request_id, auth.user.id])
  return res
})
