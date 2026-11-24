// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/gates/:id (admin) : supprime un gate créé par un administrateur,
// jamais « defaut », jamais un gate encore affecté ou utilisé par une analyse.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { deleteGate, getGate } from '../../../gates/gates'
import { gateError, uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  await withTransaction(getPool(), async (client) => {
    await client.query('LOCK TABLE gates IN SHARE ROW EXCLUSIVE MODE')
    const gate = await getGate(client, id)
    const outcome = await deleteGate(client, id)
    if (outcome === 'not-found') throw apiError(404, 'E_NOT_FOUND')
    if (outcome === 'builtin') throw gateError(409, 'E_GATE_BUILTIN')
    if (outcome === 'in-use') throw gateError(409, 'E_GATE_IN_USE')
    await writeAudit(client, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'gate.delete', outcome: 'success', targetType: 'gate', targetId: id, details: { slug: gate?.slug },
    })
  })
  setResponseStatus(event, 204)
  return null
})
