// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/deploy/projects/:id/proposals (admin) : cibles J11 proposées depuis
// les workflows du dépôt (workflow_dispatch avec une entrée scanoria_report),
// lus sans rien exécuter. Rien n'est créé sans confirmation.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { requireRole } from '../../../../utils/http'
import { requireProject } from '../../../../projects/guards'
import { proposeTargets } from '../../../../deploy/targets'
import { ForgeError } from '../../../../forges/http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  try {
    return { items: await proposeTargets(pool, project.id), error: null }
  }
  catch (err) {
    return { items: [], error: err instanceof ForgeError ? err.code : 'E_INTERNAL' }
  }
})
