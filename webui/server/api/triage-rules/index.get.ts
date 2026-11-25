// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/triage-rules[?project_id=…][&all=true] (viewer) : règles de tri en
// masse (F4) d'un projet et de toute l'appliance ; actives par défaut.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listTriageRules } from '../../findings/triage-rules'
import { UUID_RE } from '../../findings/schemas'

const query = z.strictObject({
  project_id: z.string().regex(UUID_RE).optional(),
  all: z.enum(['true', 'false']).optional(),
})

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  return { items: await listTriageRules(getPool(), { projectId: q.project_id, all: q.all === 'true' }) }
})
