// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/uploads (admin) : ouvre le téléversement d'un lot
// hors ligne ; le fichier est ensuite envoyé par PUT, en flux.

import { randomUUID } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { defineEventHandler, setResponseStatus } from 'h3'
import { getConfig } from '../../../../utils/config'
import { getPool } from '../../../../utils/db'
import { clientAddress, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = randomUUID()
  await mkdir(join(getConfig().uploadsDir, id), { mode: 0o700 })
  await writeAudit(getPool(), {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'offline.upload-start', outcome: 'success', targetType: 'upload', targetId: id,
  })
  setResponseStatus(event, 201)
  return { upload_id: id }
})
