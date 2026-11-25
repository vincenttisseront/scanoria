// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ci/issuers (admin) {kind, issuer, audience?} : ajoute un émetteur
// OIDC de confiance (HTTPS seulement, audience « scanoria » par défaut).
// Audit ci.oidc-issuer-create.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { createIssuer, getIssuer } from '../../ci/oidc'
import { issuerCreateSchema } from '../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, issuerCreateSchema)
  const pool = getPool()
  let res
  try {
    res = await createIssuer(pool, { kind: body.kind, issuer: body.issuer, audience: body.audience, createdBy: auth.user.id })
  }
  catch {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'issuer', code: 'invalid_url' }] })
  }
  if (!res.created) throw apiError(409, 'E_EXISTS')
  const row = await getIssuer(pool, res.id)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'ci.oidc-issuer-create', outcome: 'success', targetType: 'oidc-issuer', targetId: res.id,
    details: { kind: row!.kind, issuer: row!.issuer, audience: row!.audience },
  })
  setResponseStatus(event, 201)
  return row
})
