// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id/profiles (viewer) : profil effectif de chaque
// déclencheur (G9), verrous, « aucun envoi à l'IA » imposé et état de la
// configuration en code (.scanoria.yml, J8).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { projectProfilesView } from '../../../profiles/assign'
import { profileHttpError } from '../../../profiles/http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  try {
    return await projectProfilesView(pool, project.id)
  }
  catch (err) {
    profileHttpError(err)
  }
})
