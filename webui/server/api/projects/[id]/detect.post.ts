// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/detect (operator) : relance la détection F1.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { writeAudit } from '../../../utils/audit'
import { clientAddress, requireRole } from '../../../utils/http'
import { requireProject } from '../../../projects/guards'
import { publicProject, refreshDetection } from '../../../projects/service'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const updated = await refreshDetection(pool, project)
  const error = updated.detection && 'error' in updated.detection ? updated.detection.error : null
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'project.detect', outcome: error ? 'failure' : 'success', targetType: 'project', targetId: project.id,
    details: { slug: project.slug, error },
  })
  return { project: publicProject(updated) }
})
