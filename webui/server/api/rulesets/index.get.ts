// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/rulesets : jeux de règles gérés (G4), filtrables par moteur ;
// archivés sur demande. Les règles maison de l'appliance sont à part
// (GET /api/rulesets/builtin).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listRulesets, RULESET_ENGINES } from '../../rulesets/store'

const query = z.object({
  engine: z.enum(RULESET_ENGINES).optional(),
  archived: z.enum(['0', '1']).optional(),
})

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  return { items: await listRulesets(getPool(), { engine: q.engine, includeArchived: q.archived === '1' }) }
})
