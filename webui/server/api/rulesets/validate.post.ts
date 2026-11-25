// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/rulesets/validate (admin) : fait valider un contenu par son
// moteur dans le conteneur confiné du module (demande validate-ruleset), sur
// des exemples facultatifs. 202 + identifiant de demande, à suivre par
// GET /api/requests/:id.

import { defineEventHandler } from 'h3'
import { readValidated, requireRole } from '../../utils/http'
import { rulesetTestSchema, submitRulesetTest } from '../../rulesets/engine'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  return submitRulesetTest(event, await readValidated(event, rulesetTestSchema))
})
