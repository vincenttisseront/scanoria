// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/projects/:id (operator) : nom, branches suivies, planification,
// profil, gate, « aucun envoi à l'IA », jeton ou clé SSH, nouvelle archive.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { patchFromBody } from '../../../projects/update'
import { publicProject } from '../../../projects/service'
import { projectUpdateSchema } from '../../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, projectUpdateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return { project: publicProject(await patchFromBody(pool, project, body, actor)) }
})
