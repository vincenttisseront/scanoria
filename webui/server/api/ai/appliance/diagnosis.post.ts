// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/appliance/diagnosis (admin) : demande le diagnostic IA (I16)
// d'une alerte, du dernier selftest, d'une mise à jour ou d'un module. La
// console assemble un contexte masqué et neutralisé, puis dépose la tâche ;
// rien n'est fait d'autre. Sans connecteur : task_id null.

import { defineEventHandler, setResponseStatus } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { apiError, readValidated, requireRole } from '../../../utils/http'
import { requestApplianceDiagnosis } from '../../../ai/appliance'
import { APPLIANCE_SUBJECT_RE } from '../../../ai/appliance-context'

const Body = z.strictObject({
  subject_id: z.string().min(1).max(200).regex(APPLIANCE_SUBJECT_RE),
  locale: z.enum(['fr', 'en']).optional(),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, Body)
  const r = await requestApplianceDiagnosis(getPool(), body.subject_id, auth.user.id, body.locale ?? auth.user.locale)
  if (!r.found) throw apiError(404, 'E_NOT_FOUND')
  setResponseStatus(event, r.task_id ? 202 : 200)
  return { task_id: r.task_id }
})
