// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/feedback (viewer) : 👍/👎 et correction facultative sur une
// sortie IA terminée (I24). Un nouveau retour de la même personne remplace le
// précédent. La correction est masquée avant stockage ; rien n'est envoyé à
// l'IA. Sert à mesurer l'accord IA/humain (page Système › IA).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { hasRole } from '#shared/schemas'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { FeedbackBody, saveFeedback } from '../../ai/feedback'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const body = await readValidated(event, FeedbackBody)
  if (!(await saveFeedback(getPool(), body, auth.user.id, { admin: hasRole(auth.user.role, 'admin') }))) throw apiError(404, 'E_NOT_FOUND')
  return { task_id: body.task_id, vote: body.vote }
})
