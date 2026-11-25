// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/projects/:id (operator) : nom, branches suivies, planification,
// profil, « aucun envoi à l'IA », jeton ou clé SSH, nouvelle archive. Changer
// le quality gate est réservé à l'admin (un opérateur ne peut pas assouplir le
// gate de son projet).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { patchFromBody } from '../../../projects/update'
import { publicProject } from '../../../projects/service'
import { projectUpdateSchema } from '../../../projects/schemas'
import { checkDefaultProfileChange } from '../../../profiles/assign'
import { profileHttpError } from '../../../profiles/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, projectUpdateSchema)
  if (body.gate_id && body.gate_id !== project.gate_id) requireRole(event, 'admin')
  // 0.7 (G8, G9) : un profil plus souple ou archivé, mêmes règles que PUT /profiles.
  if (body.profile_id) await checkDefaultProfileChange(pool, project.id, body.profile_id, { admin: auth.user.role === 'admin' }).catch(profileHttpError)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  return { project: publicProject(await patchFromBody(pool, project, body, actor)) }
})
