// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/deploy/projects/:id/targets (lecture) : cibles de déploiement du
// projet (J11–J13), jetons jamais rendus (indice seulement).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { requireRole } from '../../../../utils/http'
import { requireProject } from '../../../../projects/guards'
import { listTargets } from '../../../../deploy/targets'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  return { items: await listTargets(pool, project.id) }
})
