// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/deploy/projects/:id/chain (lecture) : vue de la chaîne J16 (PR,
// releases, attestations, déploiements), chaque étape avec son état.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { requireRole } from '../../../../utils/http'
import { requireProject } from '../../../../projects/guards'
import { listTargets } from '../../../../deploy/targets'
import { projectChain } from '../../../../deploy/chain'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  return { ...await projectChain(pool, project.id), targets: (await listTargets(pool, project.id)).length }
})
