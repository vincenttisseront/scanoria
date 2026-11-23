// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/updates/apply (admin) : demande apply-update, depuis GitHub
// (version publiée) ou depuis un téléversement complet.

import { access, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler } from 'h3'
import { getConfig } from '../../../utils/config'
import { apiError, readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { getRunningVersion } from '../../../utils/appliance'
import { ARCHIVE_NAME_RE, UPLOAD_FILE_NAMES, requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['apply-update'])
  const cfg = getConfig()
  if (params.source === 'upload') {
    const dir = join(cfg.uploadsDir, params.upload_id)
    try {
      for (const name of UPLOAD_FILE_NAMES) await access(join(dir, name))
      if (!(await readdir(dir)).some(name => ARCHIVE_NAME_RE.test(name))) throw new Error('archive missing')
    }
    catch {
      throw apiError(400, 'E_UPLOAD')
    }
  }
  const installed = await getRunningVersion(cfg.versionFile)
  return submitHelperAction(event, 'apply-update', params, {
    dbContext: { installed_version_hint: installed },
    auditDetails: { installed_version: installed },
  })
})
