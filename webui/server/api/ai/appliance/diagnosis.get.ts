// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/appliance/diagnosis?subject_id=&locale= (admin) : dernier
// diagnostic IA (I16) d'un sujet de l'appliance, marqué IA (modèle et
// empreinte), ou l'état de la tâche ; enabled false sans connecteur.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { apiError, queryValidated, requireRole } from '../../../utils/http'
import { latestOutput } from '../../../ai/console'
import { APPLIANCE_SUBJECT_RE } from '../../../ai/appliance-context'
import { DIAGNOSE_APPLIANCE } from '../../../ai/appliance'

const Query = z.strictObject({
  subject_id: z.string().min(1).max(200).regex(APPLIANCE_SUBJECT_RE),
  locale: z.enum(['fr', 'en']).optional(),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const q = queryValidated(event, Query)
  const r = await latestOutput(getPool(), { kind: DIAGNOSE_APPLIANCE, ...q }, auth.user.locale, auth.user.id)
  if (!r) throw apiError(404, 'E_NOT_FOUND')
  return r
})
