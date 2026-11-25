// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/projects/:id/pins/:module (admin) : le projet suit de nouveau la
// version installée du module (G6) ; tracé dans l'audit.

import { defineEventHandler, getRouterParam } from 'h3'
import { apiError, requireRole } from '../../../../utils/http'
import { getPool } from '../../../../utils/db'
import { getConfig } from '../../../../utils/config'
import { requireProject } from '../../../../projects/guards'
import { publishPinsFile, unpinModule } from '../../../../vigilance/pins'
import { actorOf } from '../../../../vigilance/api'
import { MODULE_ID_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const moduleId = getRouterParam(event, 'module') ?? ''
  if (!MODULE_ID_RE.test(moduleId)) throw apiError(404, 'E_NOT_FOUND')
  if (!(await unpinModule(pool, { projectId: project.id, moduleId, actor: actorOf(event, auth).actor }))) throw apiError(404, 'E_NOT_FOUND')
  await publishPinsFile(pool, getConfig().pinsFile)
  return { ok: true }
})
