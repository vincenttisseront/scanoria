// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/modules/:module/log (viewer) : journal complet du module
// pour le diagnostic (G20), en texte brut téléchargeable. Le runner en a déjà
// retiré les jetons de la source.

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { MODULE_ID_RE } from '#shared/schemas'
import { getPool } from '../../../../../utils/db'
import { requireRole } from '../../../../../utils/http'
import { moduleLogPath, scanError, scanIdParam } from '../../../../../scans/api'
import { loadWorkerConfig } from '../../../../../scans/config'
import { MAX_LOG_BYTES } from '../../../../../scans/files'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = scanIdParam(getRouterParam(event, 'id'))
  const moduleId = getRouterParam(event, 'module') ?? ''
  if (!MODULE_ID_RE.test(moduleId)) throw scanError(404, 'E_SCAN_LOG')
  const rel = await moduleLogPath(getPool(), id, moduleId)
  if (!rel) throw scanError(404, 'E_SCAN_LOG')
  let fh
  try {
    fh = await open(join(loadWorkerConfig().scanLogsDir, rel), constants.O_RDONLY | constants.O_NOFOLLOW)
  }
  catch {
    throw scanError(404, 'E_SCAN_LOG')
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) throw scanError(404, 'E_SCAN_LOG')
    const size = Math.min(st.size, MAX_LOG_BYTES)
    const buf = Buffer.alloc(size)
    const { bytesRead } = await fh.read(buf, 0, size, 0)
    setHeader(event, 'content-type', 'text/plain; charset=utf-8')
    setHeader(event, 'content-disposition', `attachment; filename="scan-${id.slice(0, 8)}-${moduleId}.log"`)
    return buf.subarray(0, bytesRead)
  }
  finally {
    await fh.close()
  }
})
