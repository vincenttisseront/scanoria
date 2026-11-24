// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/vigilance/canaries (admin) : rejoue maintenant les canaris (G14),
// de tous les scanners installés et actifs ou de ceux de ids.

import { defineEventHandler } from 'h3'
import { readValidated, requireRole } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { canariesBodySchema } from '../../vigilance/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const body = await readValidated(event, canariesBodySchema)
  return submitHelperAction(event, 'run-canaries', body.ids ? { ids: body.ids } : {})
})
