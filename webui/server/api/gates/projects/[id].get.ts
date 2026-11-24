// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates/projects/:id (viewer) : intégration CI d'un projet : gate
// affecté, badge, adresse du badge, nombre de jetons actifs.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireAuth } from '../../../utils/http'
import { getGate, getProjectRef } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const pool = getPool()
  const project = await getProjectRef(pool, uuidParam(getRouterParam(event, 'id')))
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  const gate = await getGate(pool, project.gate_id)
  const tokens = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM api_tokens
      WHERE project_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`,
    [project.id],
  )
  return {
    project: { id: project.id, slug: project.slug, name: project.name, archived: project.archived, default_branch: project.default_branch },
    gate: gate ? { id: gate.id, slug: gate.slug, builtin: gate.builtin } : null,
    badge: { enabled: project.badge_enabled, path: `/api/badges/${project.slug}.svg` },
    active_tokens: tokens.rows[0]?.n ?? 0,
  }
})
