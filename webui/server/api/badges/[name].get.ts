// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/badges/:slug.svg (public) : badge du dernier verdict du projet.
// Désactivé par défaut (badge_enabled) : un projet inconnu ou sans badge rend
// la même réponse 404, pour ne rien révéler.

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { getPool } from '../../utils/db'
import { apiError } from '../../utils/http'
import { badgeSvg, latestVerdict } from '../../gates/badge'

export default defineEventHandler(async (event) => {
  const m = /^([a-z0-9][a-z0-9-]{0,62})\.svg$/.exec(getRouterParam(event, 'name') ?? '')
  if (!m) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const res = await pool.query<{ id: string, default_branch: string | null }>(
    'SELECT id, default_branch FROM projects WHERE slug = $1 AND badge_enabled AND archived_at IS NULL',
    [m[1]],
  )
  const project = res.rows[0]
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  setHeader(event, 'content-type', 'image/svg+xml; charset=utf-8')
  setHeader(event, 'content-security-policy', 'default-src \'none\'; style-src \'unsafe-inline\'')
  setHeader(event, 'cache-control', 'no-cache, max-age=0')
  return badgeSvg(await latestVerdict(pool, project.id, project.default_branch))
})
