// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/profiles/:id (viewer) : profil, chaîne, verrous hérités et profil
// effectif (héritage fusionné, contrat 29), projets qui l'utilisent.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { getProfile, inheritedLocks } from '../../../profiles/service'
import { effectiveProfile } from '../../../profiles/resolve'
import { profileHttpError } from '../../../profiles/http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  const pool = getPool()
  const profile = await getProfile(pool, id)
  if (!profile) throw apiError(404, 'E_NOT_FOUND')
  try {
    const [inherited, effective, projects] = await Promise.all([
      inheritedLocks(pool, profile.parent_id),
      effectiveProfile(pool, id),
      pool.query<{ id: string, slug: string, name: string, slots: string[] }>(
        `SELECT id::text, slug, name, array_remove(ARRAY[
                  CASE WHEN profile_id = $1 THEN 'default' END, CASE WHEN profile_pr_id = $1 THEN 'pr' END,
                  CASE WHEN profile_nightly_id = $1 THEN 'nightly' END, CASE WHEN profile_release_id = $1 THEN 'release' END], NULL) AS slots
           FROM projects WHERE archived_at IS NULL AND $1 IN (profile_id, profile_pr_id, profile_nightly_id, profile_release_id)
          ORDER BY name LIMIT 500`, [id]),
    ])
    return { profile, inherited_locks: inherited, effective, projects: projects.rows }
  }
  catch (err) {
    profileHttpError(err)
  }
})
