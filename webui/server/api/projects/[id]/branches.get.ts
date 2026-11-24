// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id/branches (viewer) : branches du dépôt lues sur la forge
// (choix des branches suivies), ou les branches suivies sans accès à l'API.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { mapProjectError } from '../../../projects/errors'
import { requireProject } from '../../../projects/guards'
import { projectClient } from '../../../projects/service'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  try {
    const access = await projectClient(pool, project)
    if (!access) return { live: false, items: project.tracked_branches }
    return { live: true, items: await access.client.branches(access.fullName) }
  }
  catch (err) {
    mapProjectError(err)
  }
})
