// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/forges (viewer) : forges connues, sans aucun secret (indice seulement).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { listForges } from '../../projects/forges'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return { items: await listForges(getPool()) }
})
