// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/archive (operator) : archive ou réactive un projet.
// Un projet archivé n'est plus planifié ni redécouvert ; ses données restent.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { writeAudit } from '../../../utils/audit'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { publicProject, setArchived } from '../../../projects/service'
import { archiveSchema } from '../../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, archiveSchema)
  const updated = (await setArchived(pool, project.id, body.archived))!
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: body.archived ? 'project.archive' : 'project.unarchive', outcome: 'success', targetType: 'project', targetId: project.id,
    details: { slug: project.slug },
  })
  return { project: publicProject(updated) }
})
