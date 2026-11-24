// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects (viewer) : projets actifs, ou archivés avec ?archived=1.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listProjects, publicProject } from '../../projects/service'
import { listQuerySchema } from '../../projects/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, listQuerySchema)
  const archived = q.archived === '1' || q.archived === 'true'
  const items = await listProjects(getPool(), { archived, forgeId: q.forge_id })
  return { items: items.map(publicProject) }
})
