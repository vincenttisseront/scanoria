// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/triage-rules/simulate (operator) : effet d'une règle de tri (F4)
// AVANT son enregistrement : nombre de résultats touchés par projet, et liste.
// Rien n'est écrit.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { simulateTriageRule, triageRuleSchema, TriageRuleError } from '../../findings/triage-rules'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const body = await readValidated(event, triageRuleSchema)
  try {
    return await simulateTriageRule(getPool(), body)
  }
  catch (err) {
    if (err instanceof TriageRuleError) throw apiError(400, 'E_VALIDATION', { issues: [{ path: err.detail ?? '', code: 'out_of_range' }] })
    throw err
  }
})
