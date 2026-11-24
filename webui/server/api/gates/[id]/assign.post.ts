// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/gates/:id/assign (admin) : affecte le gate à un projet. Les analyses
// suivantes l'utilisent ; une analyse déjà déposée garde le sien (G11). Audit.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { assignGate, gateAssignSchema, getGate, getProjectRef } from '../../../gates/gates'
import { gateError, uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, gateAssignSchema)
  return withTransaction(getPool(), async (client) => {
    const gate = await getGate(client, id)
    const project = await getProjectRef(client, body.project_id)
    if (!gate || !project) throw apiError(404, 'E_NOT_FOUND')
    if (project.archived) throw gateError(409, 'E_PROJECT_ARCHIVED')
    const res = await assignGate(client, id, project.id)
    await writeAudit(client, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'gate.assign', outcome: 'success', targetType: 'project', targetId: project.id,
      details: { project: project.slug, gate: gate.slug, from_gate_id: res?.from ?? null },
    })
    return { project_id: project.id, gate_id: id }
  })
})
