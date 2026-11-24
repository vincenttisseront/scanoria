// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/projects/:id (admin) : suppression définitive (analyses et
// résultats compris). Le corps doit répéter le slug du projet ({confirm}) :
// la modale de la console le fait saisir. L'archivage reste la voie normale.
// Un dépôt d'une forge dont la découverte est active serait recréé à la
// découverte suivante : la suppression est alors refusée (archiver, ou couper
// la découverte de la forge d'abord).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { writeAudit } from '../../../utils/audit'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { projectError } from '../../../projects/errors'
import { requireProject } from '../../../projects/guards'
import { deleteProject } from '../../../projects/service'
import { removeUpload } from '../../../projects/uploads'
import { deleteSchema } from '../../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, deleteSchema)
  if (body.confirm !== project.slug) throw projectError(400, 'E_CONFIRM')
  if (project.forge_id) {
    const f = await pool.query(`SELECT 1 FROM forges WHERE id = $1 AND discovery`, [project.forge_id])
    if (f.rowCount) throw projectError(409, 'E_PROJECT_DISCOVERED')
  }
  await deleteProject(pool, project.id)
  await removeUpload(project.upload_id)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'project.delete', outcome: 'success', targetType: 'project', targetId: project.id,
    details: { slug: project.slug, name: project.name },
  })
  return { deleted: true }
})
