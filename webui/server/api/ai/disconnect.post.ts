// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/disconnect (admin) : retire le connecteur ; le helper referme
// la sortie de scanoria-ai. Les tâches en file sont ignorées, rien n'est envoyé.

import { defineEventHandler } from 'h3'
import { requireRole } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  return submitHelperAction(event, 'set-ai-endpoint', { enabled: false })
})
