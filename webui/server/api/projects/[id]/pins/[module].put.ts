// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/projects/:id/pins/:module {reason} (admin) : fige pour ce projet la
// version installée du module (G6) ; motif obligatoire, tracé dans l'audit.

import { defineEventHandler, getRouterParam } from 'h3'
import { apiError, readValidated, requireRole } from '../../../../utils/http'
import { getPool } from '../../../../utils/db'
import { getConfig } from '../../../../utils/config'
import { requireProject } from '../../../../projects/guards'
import { loadCatalogContext } from '../../../../utils/catalog-view'
import { PinError, pinModule, publishPinsFile } from '../../../../vigilance/pins'
import { actorOf, pinBodySchema } from '../../../../vigilance/api'
import { MODULE_ID_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const moduleId = getRouterParam(event, 'module') ?? ''
  if (!MODULE_ID_RE.test(moduleId)) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, pinBodySchema)
  const ctx = await loadCatalogContext()
  try {
    const pin = await pinModule(pool, {
      projectId: project.id, moduleId, reason: body.reason, actor: actorOf(event, auth).actor,
      installed: ctx.installed, index: ctx.index,
    })
    // Le helper doit connaître la version figée avant toute mise à jour du module.
    await publishPinsFile(pool, getConfig().pinsFile)
    return { pin }
  }
  catch (e) {
    if (e instanceof PinError) throw apiError(409, 'E_PRECONDITION', { reason: e.code })
    throw e
  }
})
