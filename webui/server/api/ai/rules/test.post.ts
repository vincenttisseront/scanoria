// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/rules/test (operator) : teste la règle proposée (I12) dans le
// conteneur confiné de son moteur, sans réseau, sur ses exemples positif et
// négatif. La règle et les exemples viennent de la sortie de la tâche, jamais
// du corps de la demande.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { RuleQuery, testRule } from '../../../ai/rulegen'
import { rulegenHttpError } from '../../../ai/rulegen-http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, RuleQuery)
  try {
    return await testRule(getPool(), body.subject_id, auth.user.id)
  }
  catch (err) {
    throw rulegenHttpError(err)
  }
})
