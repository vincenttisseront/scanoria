// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/profiles (viewer) : profils, hiérarchie et verrous (G8) ; ?archived=1 inclut les archivés.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listProfiles } from '../../profiles/service'

const query = z.strictObject({ archived: z.enum(['0', '1', 'true', 'false']).optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  return { items: await listProfiles(getPool(), { archived: q.archived === '1' || q.archived === 'true' }) }
})
