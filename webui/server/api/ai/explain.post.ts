// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/explain (viewer) : demande interactive d'explication d'un
// résultat (I2) ou d'un verdict (I9), prioritaire sur les précalculs.
// Sans connecteur ou pour un projet « aucun envoi à l'IA » : task_id null.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { ExplainBody, requestExplanation } from '../../ai/console'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const body = await readValidated(event, ExplainBody)
  const r = await requestExplanation(getPool(), body, auth.user.id, auth.user.locale)
  if (!r.found) throw apiError(404, 'E_NOT_FOUND')
  setResponseStatus(event, r.task_id ? 202 : 200)
  return { task_id: r.task_id }
})
