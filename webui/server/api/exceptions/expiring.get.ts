// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/exceptions/expiring[?project_id=…] (viewer) : exceptions approuvées
// qui expirent dans les 14 jours (bandeau d'échéance, F5). Échues, elles
// redeviennent bloquantes d'elles-mêmes.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { EXPIRY_NOTICE_DAYS, listExpiringExceptions } from '../../findings/exceptions'
import { UUID_RE } from '../../findings/schemas'

const query = z.strictObject({ project_id: z.string().regex(UUID_RE).optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  return { days: EXPIRY_NOTICE_DAYS, items: await listExpiringExceptions(getPool(), q.project_id) }
})
