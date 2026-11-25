// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/rules/rulesets?engine= (admin) : jeux de règles G4 actifs d'un
// moteur, proposés pour enregistrer une règle générée par IA (I12).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { queryValidated, requireRole } from '../../../utils/http'
import { listRulesetsFor } from '../../../ai/rulegen'
import { RULE_ENGINES } from '../../../ai/tasks/rulegen'
import { rulegenHttpError } from '../../../ai/rulegen-http'

const Query = z.strictObject({ engine: z.enum(RULE_ENGINES) })

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const q = queryValidated(event, Query)
  try {
    return { items: await listRulesetsFor(getPool(), q.engine) }
  }
  catch (err) {
    throw rulegenHttpError(err)
  }
})
