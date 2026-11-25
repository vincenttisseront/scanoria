// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/triage-rules/proposals?project_id=… (viewer) : règles de tri F4
// PROPOSÉES à partir du pré-tri IA (I3), quand plusieurs résultats nouveaux
// partagent la même raison citée. Lecture seule : l'enregistrement reste un
// clic d'une personne (POST /api/triage-rules), après simulation. Vide sans
// connecteur et pour un projet « aucun envoi à l'IA ».

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { proposeTriageRules } from '../../findings/triage-rules'
import { connectorEnabled } from '../../ai/enqueue'
import { UUID_RE } from '../../findings/schemas'

const query = z.strictObject({ project_id: z.string().regex(UUID_RE) })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  if (!(await connectorEnabled())) return { enabled: false, items: [] }
  return { enabled: true, items: await proposeTriageRules(getPool(), q.project_id) }
})
