// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/tokens (operator) : crée un jeton « scn_… » pour la CI.
// La valeur n'est renvoyée qu'une fois ; seule l'empreinte SHA-256 est gardée.
// Audit api-token.create (sans la valeur).

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { createApiToken } from '../../../gates/tokens'
import { getProjectRef, tokenCreateSchema } from '../../../gates/gates'
import { gateError, uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, tokenCreateSchema)
  const pool = getPool()
  const project = await getProjectRef(pool, id)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  if (project.archived) throw gateError(409, 'E_PROJECT_ARCHIVED')
  const { token, row } = await createApiToken(pool, { projectId: id, name: body.name, expiresInDays: body.expires_in_days ?? null, createdBy: auth.user.id })
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'api-token.create', outcome: 'success', targetType: 'api-token', targetId: row.id,
    details: { project: project.slug, name: row.name, prefix: row.prefix, expires_at: row.expires_at },
  })
  setResponseStatus(event, 201)
  return { ...row, value: token }
})
