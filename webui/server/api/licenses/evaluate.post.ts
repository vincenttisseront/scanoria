// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/licenses/evaluate (viewer) : décision d'une expression SPDX pour
// la politique globale ou celle d'un projet (aperçu dans la console).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { readValidated, requireRole } from '../../utils/http'
import { decideExpression, loadPolicy } from '../../licenses/policy'
import { MAX_EXPRESSION } from '../../licenses/spdx'

const bodySchema = z.strictObject({
  expression: z.string().min(1).max(MAX_EXPRESSION),
  project_id: z.string().uuid().nullable().optional(),
})

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const body = await readValidated(event, bodySchema)
  return decideExpression(await loadPolicy(getPool(), body.project_id ?? null), body.expression)
})
