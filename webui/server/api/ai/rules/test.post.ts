// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/rules/test (admin) : dépose le test de la règle proposée (I12)
// dans le conteneur confiné de son moteur, sans réseau, sur ses exemples
// positif et négatif (demande validate-ruleset des jeux de règles G4). La règle
// et les exemples viennent de la sortie de la tâche, jamais du corps de la
// demande. 202 + identifiant de demande, suivi par GET /api/requests/:id, puis
// verdict par GET /api/ai/rules/test.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { RuleQuery, testRule } from '../../../ai/rulegen'
import { rulegenHttpError } from '../../../ai/rulegen-http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const body = await readValidated(event, RuleQuery)
  try {
    return await testRule(event, getPool(), body.subject_id)
  }
  catch (err) {
    throw rulegenHttpError(err)
  }
})
