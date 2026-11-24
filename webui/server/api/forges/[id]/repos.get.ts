// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/forges/:id/repos (operator) : dépôts accessibles, lus en direct sur
// la forge, avec le projet correspondant s'il existe (assistant d'ajout).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { openForge } from '../../../forges'
import { mapProjectError } from '../../../projects/errors'
import { requireForge } from '../../../projects/guards'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const pool = getPool()
  const forge = await requireForge(pool, getRouterParam(event, 'id'))
  let repos
  try {
    repos = await (await openForge(pool, forge)).listRepos()
  }
  catch (err) {
    mapProjectError(err)
  }
  const { rows } = await pool.query<{ id: string, repo_full_name: string }>(
    'SELECT id::text, repo_full_name FROM projects WHERE forge_id = $1 AND repo_full_name IS NOT NULL', [forge.id])
  const known = new Map(rows.map(r => [r.repo_full_name.toLowerCase(), r.id]))
  return {
    items: repos.map(r => ({ ...r, project_id: known.get(r.full_name.toLowerCase()) ?? null })),
  }
})
