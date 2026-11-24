// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/admin-password/reveal {request_id} (admin) :
// mot de passe administrateur produit par reset-service-admin, rendu une seule
// fois à l'administrateur qui l'a demandé ; jamais mis en cache ni journalisé.

import { defineEventHandler, setHeader } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../../../utils/db'
import { writeAudit } from '../../../../../utils/audit'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../../utils/http'
import { installedModuleParam } from '../../../../../utils/catalog-actions'
import { managesAdmin, revealAdminPassword } from '../../../../../services/admin-access'

const bodySchema = z.strictObject({ request_id: z.uuid() })
const STATUS = { E_NOT_FOUND: 404, E_FORBIDDEN: 403, E_PRECONDITION: 409, E_GONE: 410 } as const

export default defineEventHandler(async (event) => {
  const { id } = await installedModuleParam(event)
  if (!managesAdmin(id)) throw apiError(409, 'E_PRECONDITION')
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, bodySchema)
  const pool = getPool()
  const res = await revealAdminPassword(pool, { requestId: body.request_id, moduleId: id, userId: String(auth.user.id) })
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'modules.admin-password.reveal',
    outcome: res.ok ? 'success' : 'failure',
    targetType: 'module',
    targetId: id,
    requestId: body.request_id,
    details: res.ok ? {} : { error: res.code },
  }).catch(() => {})
  if (!res.ok) throw apiError(STATUS[res.code], res.code)
  setHeader(event, 'cache-control', 'no-store')
  return { login: res.login, password: res.password }
})
