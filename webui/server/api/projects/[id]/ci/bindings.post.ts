// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/ci/bindings (admin) {issuer_id, repository,
// ref_patterns?} : liaison OIDC d'un dépôt vers ce projet (J4). Audit
// ci.oidc-binding-create.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { uuidParam } from '../../../../gates/http'
import { getProjectRef } from '../../../../gates/gates'
import { createBinding, getIssuer, listBindings } from '../../../../ci/oidc'
import { bindingCreateSchema } from '../../../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, bindingCreateSchema)
  const pool = getPool()
  const project = await getProjectRef(pool, id)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  const issuer = await getIssuer(pool, body.issuer_id.toLowerCase())
  if (!issuer) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'issuer_id', code: 'unknown_issuer' }] })
  const bindingId = await createBinding(pool, { issuerId: issuer.id, projectId: id, repository: body.repository, refPatterns: body.ref_patterns })
  if (!bindingId) throw apiError(409, 'E_EXISTS')
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'ci.oidc-binding-create', outcome: 'success', targetType: 'project', targetId: id,
    details: { binding: bindingId, issuer: issuer.issuer, repository: body.repository, ref_patterns: body.ref_patterns ?? null },
  })
  setResponseStatus(event, 201)
  return (await listBindings(pool, id)).find(b => b.id === bindingId)
})
