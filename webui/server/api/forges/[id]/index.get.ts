// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/forges/:id (viewer) : une forge et ses projets découverts.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { forgeView } from '../../../projects/forges'
import { listProjects, publicProject } from '../../../projects/service'
import { requireForge } from '../../../projects/guards'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const forge = await requireForge(pool, getRouterParam(event, 'id'))
  const projects = await listProjects(pool, { forgeId: forge.id })
  return { forge: await forgeView(pool, forge), projects: projects.map(publicProject) }
})
