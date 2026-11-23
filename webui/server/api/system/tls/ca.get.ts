// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/system/tls/ca : certificat de l'AC interne à installer sur les postes
// (copie publique /var/lib/scanoria/public/scanoria-ca.crt).

import { lstat, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler, setHeader } from 'h3'
import { getConfig } from '../../../utils/config'
import { apiError, requireAuth } from '../../../utils/http'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const path = join(getConfig().publicFilesDir, 'scanoria-ca.crt')
  try {
    const st = await lstat(path)
    if (!st.isFile() || st.size > 64 * 1024) throw new Error('not a regular file')
    const pem = await readFile(path, 'utf8')
    if (!pem.startsWith('-----BEGIN CERTIFICATE-----')) throw new Error('not a certificate')
    setHeader(event, 'content-type', 'application/x-pem-file')
    setHeader(event, 'content-disposition', 'attachment; filename="scanoria-ca.crt"')
    return pem
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
})
