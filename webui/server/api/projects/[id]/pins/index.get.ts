// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id/pins (lecteur) : versions de modules figées par le
// projet (G6), avec leurs avertissements (retirée du catalogue, vulnérable,
// absente de la machine), et modules installés que l'on peut figer.

import { defineEventHandler, getRouterParam } from 'h3'
import { requireAuth } from '../../../../utils/http'
import { getPool } from '../../../../utils/db'
import { requireProject } from '../../../../projects/guards'
import { loadCatalogContext } from '../../../../utils/catalog-view'
import { projectPinsView } from '../../../../vigilance/api'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  return projectPinsView(pool, project.id, await loadCatalogContext())
})
