// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/rules (operator) : demande d'une règle générée par IA (I12)
// depuis un résultat, un exemple de code ou une phrase. Rien n'est enregistré :
// la règle est ensuite testée, puis confirmée par un administrateur.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { GenerateBody, requestRule } from '../../ai/rulegen'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, GenerateBody)
  const r = await requestRule(getPool(), body, auth.user.id, auth.user.locale)
  if (!r.found) throw apiError(404, 'E_NOT_FOUND')
  setResponseStatus(event, r.task_id ? 202 : 200)
  return { subject_id: r.subject_id, task_id: r.task_id }
})
