// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/agreement (operator) : taux d'accord IA/humain par tâche et
// par modèle sur 90 jours (I24) : part des 👍, et pour le pré-tri (I3) part
// des suggestions confirmées par le tri fait ensuite par une personne.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { agreement } from '../../ai/feedback'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  return { days: 90, items: await agreement(getPool(), 90) }
})
