// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/releases?project=<id> (viewer) : releases vues d'un projet (tags
// en mode tiré ou poussé), avec l'état de leur analyse et de leur rapport.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listReleases } from '../../release/api'

const Query = z.object({ project: z.uuid(), limit: z.coerce.number().int().min(1).max(200).default(50) })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, Query)
  return { items: await listReleases(getPool(), q.project.toLowerCase(), q.limit) }
})
