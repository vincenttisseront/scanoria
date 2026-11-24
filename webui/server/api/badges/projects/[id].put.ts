// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/badges/projects/:id (operator) : active ou désactive le badge public
// du projet (désactivé par défaut). Audit project.badge.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { badgeUpdateSchema, getProjectRef } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, badgeUpdateSchema)
  const pool = getPool()
  const project = await getProjectRef(pool, id)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  await pool.query('UPDATE projects SET badge_enabled = $2 WHERE id = $1', [id, body.enabled])
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'project.badge', outcome: 'success', targetType: 'project', targetId: id,
    details: { project: project.slug, enabled: body.enabled },
  })
  return { project_id: id, enabled: body.enabled, path: `/api/badges/${project.slug}.svg` }
})
