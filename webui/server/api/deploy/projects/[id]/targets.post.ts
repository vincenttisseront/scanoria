// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/deploy/projects/:id/targets (admin) : déclare une cible de
// déploiement (J11 CD, J12 GitOps, J13 registre), tracée dans l'audit.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { requireProject } from '../../../../projects/guards'
import { createTarget } from '../../../../deploy/targets'
import { targetCreateSchema } from '../../../../deploy/config'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, targetCreateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const target = await createTarget(pool, project.id, body, actor)
  setResponseStatus(event, 201)
  return { target }
})
