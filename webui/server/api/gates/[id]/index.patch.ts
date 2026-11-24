// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/gates/:id (admin) : nouvelles règles (GateRules ; H4 et G13 ne
// peuvent pas être désactivés). Audit gate.update avec l'avant et l'après.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { gateUpdateSchema, getGate, updateGateRules } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, gateUpdateSchema)
  return withTransaction(getPool(), async (client) => {
    const before = await getGate(client, id)
    if (!before) throw apiError(404, 'E_NOT_FOUND')
    const after = await updateGateRules(client, id, body.rules, auth.user.id)
    const changes: Record<string, { from: unknown, to: unknown }> = {}
    for (const [k, v] of Object.entries(body.rules)) {
      const old = (before.rules as Record<string, unknown>)[k]
      if (old !== v) changes[k] = { from: old ?? null, to: v }
    }
    await writeAudit(client, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'gate.update', outcome: 'success', targetType: 'gate', targetId: id,
      details: { slug: before.slug, changes },
    })
    return after
  })
})
