// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/projects/:id/ci/bindings/:binding (admin) : retire une liaison
// OIDC ; les jetons de ce dépôt sont refusés aussitôt. Audit ci.oidc-binding-delete.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../../../utils/http'
import { writeAudit } from '../../../../../utils/audit'
import { uuidParam } from '../../../../../gates/http'
import { deleteBinding } from '../../../../../ci/oidc'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const bindingId = uuidParam(getRouterParam(event, 'binding'))
  const pool = getPool()
  if (!(await deleteBinding(pool, id, bindingId))) throw apiError(404, 'E_NOT_FOUND')
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'ci.oidc-binding-delete', outcome: 'success', targetType: 'project', targetId: id, details: { binding: bindingId },
  })
  setResponseStatus(event, 204)
  return null
})
