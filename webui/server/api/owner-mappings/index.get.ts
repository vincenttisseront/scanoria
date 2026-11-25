// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/owner-mappings[?project_id=…] (viewer) : correspondances entre
// responsables CODEOWNERS et comptes de la console (F6).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listOwnerMappings } from '../../findings/owners'
import { UUID_RE } from '../../findings/schemas'

const query = z.strictObject({ project_id: z.string().regex(UUID_RE).optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  return { items: await listOwnerMappings(getPool(), q.project_id) }
})
