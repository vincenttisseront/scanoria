// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/exceptions/pending-count (viewer) : compteur de la navigation.
// Seuls les administrateurs décident : pour les autres rôles, 0.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireAuth } from '../../utils/http'
import { hasRole } from '#shared/schemas'
import { countPendingExceptions } from '../../findings/exceptions'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  return { count: hasRole(auth.user.role, 'admin') ? await countPendingExceptions(getPool()) : 0 }
})
