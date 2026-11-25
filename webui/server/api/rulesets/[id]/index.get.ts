// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/rulesets/:id : jeu de règles, historique des versions, profils
// rattachés et profils disponibles pour le rattachement.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { getRuleset, listAttachments, listVersions } from '../../../rulesets/store'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const pool = getPool()
  const rs = await getRuleset(pool, getRouterParam(event, 'id') ?? '')
  if (!rs) throw apiError(404, 'E_NOT_FOUND')
  const [versions, attachments, profiles] = await Promise.all([
    listVersions(pool, rs.id),
    listAttachments(pool, rs.id),
    pool.query<{ id: string, slug: string, builtin: boolean }>('SELECT id::text, slug, builtin FROM profiles ORDER BY builtin DESC, slug LIMIT 500'),
  ])
  return { ruleset: rs, versions, attachments, profiles: profiles.rows }
})
