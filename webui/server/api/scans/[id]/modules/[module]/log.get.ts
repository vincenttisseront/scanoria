// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/modules/:module/log (operator) : journal complet du
// module pour le diagnostic (G20), en texte brut téléchargeable. Le worker en
// a retiré le secret de la source ; le masquage commun est repassé ici (aucun
// motif de secret ne sort), taille bornée, troncature signalée. Audité.

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { MODULE_ID_RE } from '#shared/schemas'
import { getPool } from '../../../../../utils/db'
import { requireRole } from '../../../../../utils/http'
import { auditScanAction, moduleLogPath, scanError, scanIdParam } from '../../../../../scans/api'
import { loadWorkerConfig } from '../../../../../scans/config'
import { MAX_LOG_DOWNLOAD, readModuleLog } from '../../../../../health/log'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = scanIdParam(getRouterParam(event, 'id'))
  const moduleId = getRouterParam(event, 'module') ?? ''
  if (!MODULE_ID_RE.test(moduleId)) throw scanError(404, 'E_SCAN_LOG')
  const log = await readModuleLog(loadWorkerConfig().scanLogsDir, await moduleLogPath(getPool(), id, moduleId))
  if (!log) throw scanError(404, 'E_SCAN_LOG')
  await auditScanAction(event, auth, 'scan.log-download', id, 'success', { module: moduleId, truncated: log.truncated })
  setHeader(event, 'content-type', 'text/plain; charset=utf-8')
  setHeader(event, 'content-disposition', `attachment; filename="scan-${id.slice(0, 8)}-${moduleId}.log"`)
  setHeader(event, 'cache-control', 'no-store')
  return log.truncated
    ? `[journal tronqué : début et fin, ${MAX_LOG_DOWNLOAD} octets au plus / log truncated: head and tail, at most ${MAX_LOG_DOWNLOAD} bytes]\n${log.text}`
    : log.text
})
