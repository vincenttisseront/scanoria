// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/status (operator) : connecteur IA, modèles retenus et pourquoi,
// banc d'essai, disjoncteur, latence, file (CLAUDE.md § 3.5, I1, I23).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { aiStatus } from '../../ai/console'
import { tokenStoreAvailable } from '../../ai/token'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  return { ...(await aiStatus(getPool())), token_supported: tokenStoreAvailable() }
})
