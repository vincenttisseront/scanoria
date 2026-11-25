// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/projects/:id/profiles (operator) : profils par déclencheur (G9) ;
// null rend l'emplacement au profil par défaut. Remplacer un profil par un
// profil aux verrous plus souples est réservé à l'administrateur (403
// E_FORBIDDEN, détail E_PROFILE_LOOSER). Audit project.profiles.

import { createError, defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { requireProject } from '../../../projects/guards'
import { assignProfiles, projectProfilesSchema, projectProfilesView } from '../../../profiles/assign'
import { profileHttpError } from '../../../profiles/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  if (project.archived_at) throw createError({ statusCode: 409, statusMessage: 'E_ARCHIVED', data: { code: 'E_ARCHIVED' } })
  const body = await readValidated(event, projectProfilesSchema)
  try {
    await withTransaction(pool, async (client) => {
      const { changed, imposed } = await assignProfiles(client, project.id, body, { admin: auth.user.role === 'admin' })
      await writeAudit(client, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'project.profiles', outcome: 'success', targetType: 'project', targetId: project.id,
        details: { slug: project.slug, changed, ai_opt_out_imposed: imposed },
      })
    })
    return await projectProfilesView(pool, project.id)
  }
  catch (err) {
    profileHttpError(err)
  }
})
