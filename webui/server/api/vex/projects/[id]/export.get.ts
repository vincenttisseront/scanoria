// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/vex/projects/:id/export?format=openvex|cyclonedx&scan_id= (viewer) :
// H7, document VEX canonique du projet, ou des vulnérabilités vues par une
// analyse, en fichier téléchargeable. L'en-tête x-scanoria-sha256 porte
// l'empreinte des octets rendus. Audité.

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, queryValidated, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { uuidParam } from '../../../../gates/http'
import { exportVex, VexError } from '../../../../vex/vex'

const Query = z.strictObject({
  format: z.enum(['openvex', 'cyclonedx']).default('openvex'),
  scan_id: z.string().uuid().optional(),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const q = queryValidated(event, Query)
  let out
  try {
    out = await exportVex(getPool(), projectId, { format: q.format, scanId: q.scan_id ?? null })
  }
  catch (err) {
    if (err instanceof VexError) throw apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code)
    throw err
  }
  await writeAudit(getPool(), {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'vex.export', outcome: 'success', targetType: 'project', targetId: projectId,
    details: { format: q.format, scan_id: q.scan_id ?? null, statements: out.count, sha256: out.sha256 },
  })
  setHeader(event, 'content-type', `${out.contentType}; charset=utf-8`)
  setHeader(event, 'content-disposition', `attachment; filename="${out.filename}"`)
  setHeader(event, 'cache-control', 'no-store')
  setHeader(event, 'x-scanoria-sha256', out.sha256)
  return out.body
})
