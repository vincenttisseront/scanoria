// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/system/offline/bundles/:name (admin) : téléchargement en flux d'un
// lot exporté (root:scanoria 0640 sous /var/lib/scanoria/bundles). Le nom est
// contrôlé par motif : aucun chemin choisi par le client n'est suivi.

import { open } from 'node:fs/promises'
import { constants } from 'node:fs'
import { join } from 'node:path'
import { defineEventHandler, getRouterParam, sendStream, setResponseHeader } from 'h3'
import { getConfig } from '../../../../utils/config'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { BUNDLE_NAME_RE } from '../../../../offline/status'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const name = getRouterParam(event, 'name') ?? ''
  if (!BUNDLE_NAME_RE.test(name)) throw apiError(404, 'E_NOT_FOUND')
  const path = join(getConfig().bundlesDir ?? '/var/lib/scanoria/bundles', name)
  let fh
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
  const st = await fh.stat()
  if (!st.isFile()) {
    await fh.close()
    throw apiError(404, 'E_NOT_FOUND')
  }
  await writeAudit(getPool(), {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'offline.bundle-download', outcome: 'success', targetType: 'bundle', targetId: name,
  })
  setResponseHeader(event, 'Content-Type', 'application/x-tar')
  setResponseHeader(event, 'Content-Length', st.size)
  setResponseHeader(event, 'Content-Disposition', `attachment; filename="${name}"`)
  setResponseHeader(event, 'X-Content-Type-Options', 'nosniff')
  return sendStream(event, fh.createReadStream({ autoClose: true }))
})
