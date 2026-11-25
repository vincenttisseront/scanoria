// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/agreement (operator) : taux d'accord IA/humain par tâche et
// par modèle sur 90 jours (I24) : part des 👍, et pour le pré-tri (I3) part
// des suggestions confirmées par le tri fait ensuite par une personne.
// 0.7 (contrat 32) : modules d'analyse par IA, part des résultats confirmés
// parmi ceux qu'une personne a tranchés (confirmé ou faux positif).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { agreement } from '../../ai/feedback'
import { aiModuleAgreement } from '../../findings/ai-findings'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const pool = getPool()
  return { days: 90, items: await agreement(pool, 90), modules: await aiModuleAgreement(pool, 90) }
})
