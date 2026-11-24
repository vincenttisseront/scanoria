// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/licenses/policy (viewer) : politique de licences (F8). Défauts
// versionnés, politique globale et, avec ?project_id=, surcharges du projet.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { queryValidated, requireRole } from '../../../utils/http'
import { DEFAULT_ALLOWED, DEFAULT_POLICY_VERSION, listPolicyRows } from '../../../licenses/policy'

const querySchema = z.object({ project_id: z.string().uuid().optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, querySchema)
  const pool = getPool()
  const overrides = await pool.query<{ project_id: string, slug: string, name: string, count: number }>(
    `SELECT p.id::text AS project_id, p.slug, p.name, count(*)::int AS count
       FROM license_policies l JOIN projects p ON p.id = l.project_id
      GROUP BY p.id ORDER BY p.slug LIMIT 1000`)
  return {
    defaults: { version: DEFAULT_POLICY_VERSION, allowed: DEFAULT_ALLOWED, otherwise: 'review' as const, unknown: 'review' as const },
    global: await listPolicyRows(pool, null),
    project: q.project_id ? await listPolicyRows(pool, q.project_id) : null,
    projects_with_overrides: overrides.rows,
  }
})
