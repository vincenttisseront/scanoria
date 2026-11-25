// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/rules/test?subject_id=&request_id= (operator) : verdict du test
// d'une règle proposée (I12) à partir de la demande validate-ruleset, qui doit
// porter exactement cette règle et ses exemples. done = false tant qu'elle
// est en cours.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { queryValidated, requireRole } from '../../../utils/http'
import { ruleVerdict, VerdictQuery } from '../../../ai/rulegen'
import { rulegenHttpError } from '../../../ai/rulegen-http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const q = queryValidated(event, VerdictQuery)
  try {
    return await ruleVerdict(getPool(), q.subject_id, q.request_id)
  }
  catch (err) {
    throw rulegenHttpError(err)
  }
})
