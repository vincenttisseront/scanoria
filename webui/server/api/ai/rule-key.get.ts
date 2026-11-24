// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/rule-key?finding_id= (viewer) : clé « outil:version:règle » de
// la traduction (I17) de la règle d'un résultat ; key null quand rien n'est
// traduit (secret, projet « aucun envoi à l'IA », règle hors format).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { RuleKeyQuery, ruleKeyOf } from '../../ai/console'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const r = await ruleKeyOf(getPool(), queryValidated(event, RuleKeyQuery).finding_id)
  if (!r.found) throw apiError(404, 'E_NOT_FOUND')
  return { key: r.key }
})
