// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/projects/:id/ci/bindings/:binding (admin) {ref_patterns?,
// reset_repository_id?} : motifs de ref admis pour une liaison OIDC, ou
// réinitialisation de l'identifiant de dépôt épinglé (migration 019). Audits
// ci.oidc-binding-update et ci.oidc-binding-reset-pin.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../../utils/http'
import { writeAudit } from '../../../../../utils/audit'
import { uuidParam } from '../../../../../gates/http'
import { listBindings, resetBindingPin, updateBinding } from '../../../../../ci/oidc'
import { bindingPatchSchema } from '../../../../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const bindingId = uuidParam(getRouterParam(event, 'binding'))
  const body = await readValidated(event, bindingPatchSchema)
  const pool = getPool()
  const before = (await listBindings(pool, id)).find(b => b.id === bindingId)
  if (!before) throw apiError(404, 'E_NOT_FOUND')
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  if (body.ref_patterns) {
    await updateBinding(pool, id, bindingId, { refPatterns: body.ref_patterns })
    await writeAudit(pool, {
      actor, action: 'ci.oidc-binding-update', outcome: 'success', targetType: 'project', targetId: id,
      details: { binding: bindingId, ref_patterns: body.ref_patterns },
    })
  }
  if (body.reset_repository_id) {
    await resetBindingPin(pool, id, bindingId)
    await writeAudit(pool, {
      actor, action: 'ci.oidc-binding-reset-pin', outcome: 'success', targetType: 'project', targetId: id,
      details: { binding: bindingId, repository: before.repository, previous_repository_id: before.repository_id },
    })
  }
  return (await listBindings(pool, id)).find(b => b.id === bindingId)
})
