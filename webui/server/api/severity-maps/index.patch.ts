// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/severity-maps (admin) : modifie la gravité normalisée d'une
// gravité native (G5), ou revient à la valeur d'origine (severity: null).
// Toute modification est auditée.

import { defineEventHandler } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { updateSeverityMap } from '../../findings/severity'
import { readModuleHints } from '../../findings/manifest'
import { severityUpdateSchema } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, severityUpdateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const manifestMap = (await readModuleHints(body.module_id)).severityMap
  const res = await withTransaction(getPool(), async (db) => {
    const changed = await updateSeverityMap(db, body.module_id, body.native, body.severity, auth.user.id, manifestMap)
    if (changed) {
      await writeAudit(db, {
        actor, action: body.severity === null ? 'severity-map.reset' : 'severity-map.update', outcome: 'success',
        targetType: 'severity-map', targetId: `${body.module_id}:${body.native}`,
        details: { module_id: body.module_id, native: body.native, from: changed.before, to: changed.after },
      })
    }
    return changed
  })
  if (!res) throw apiError(404, 'E_NOT_FOUND')
  return { module_id: body.module_id, native: body.native, severity: res.after, builtin: body.severity === null }
})
