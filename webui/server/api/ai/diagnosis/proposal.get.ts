// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/diagnosis/proposal?scan_id= (operator) : réglage de ressources
// sûr pour une analyse en échec (I15), recalculé depuis les faits : délai
// d'un module arrivé à sa limite, doublé et plafonné. null sinon.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { queryValidated, requireRole } from '../../../utils/http'
import { loadTimeoutOverrides, timeoutProposal } from '../../../ai/console'

const Query = z.strictObject({ scan_id: z.uuid() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const q = queryValidated(event, Query)
  const pool = getPool()
  return { proposal: await timeoutProposal(pool, q.scan_id), overrides: await loadTimeoutOverrides(pool) }
})
