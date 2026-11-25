// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/rules?subject_id= (operator) : règle proposée par IA (I12),
// avec ses exemples positif et négatif, une fois la sortie validée.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { readRule, RuleReadQuery } from '../../ai/rulegen'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const q = queryValidated(event, RuleReadQuery)
  const r = await readRule(getPool(), q.subject_id)
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return r
})
