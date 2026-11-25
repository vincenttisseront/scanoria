// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/ci/issuers/:id (admin) {enabled} : active ou désactive un
// émetteur OIDC. Désactivé, tout jeton de cet émetteur est refusé ; il n'est
// jamais réactivé automatiquement. Audit ci.oidc-issuer-enable / -disable.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { uuidParam } from '../../../gates/http'
import { getIssuer, setIssuerEnabled } from '../../../ci/oidc'
import { issuerPatchSchema } from '../../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, issuerPatchSchema)
  const pool = getPool()
  if (!(await setIssuerEnabled(pool, id, body.enabled))) throw apiError(404, 'E_NOT_FOUND')
  const row = await getIssuer(pool, id)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: body.enabled ? 'ci.oidc-issuer-enable' : 'ci.oidc-issuer-disable', outcome: 'success', targetType: 'oidc-issuer', targetId: id,
    details: { issuer: row?.issuer ?? null },
  })
  return row
})
