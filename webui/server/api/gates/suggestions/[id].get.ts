// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/gates/suggestions/:taskId (viewer) : I19, règles candidates d'une
// proposition de l'IA (règles du gate du projet, seuils proposés), pour
// préremplir la page du gate. Marquées IA : modèle et empreinte.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { suggestionByTask } from '../../../gates/suggest'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const s = await suggestionByTask(getPool(), uuidParam(getRouterParam(event, 'id')))
  if (!s) throw apiError(404, 'E_NOT_FOUND')
  return {
    task_id: s.task_id, project_id: s.project_id, gate_id: s.gate_id, gate_slug: s.gate_slug, rules: s.rules,
    rationale: s.output.rationale, exceptions: s.output.exceptions, model: s.model, model_digest: s.model_digest,
  }
})
