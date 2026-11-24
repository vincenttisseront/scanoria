// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/intel/status (viewer) : état de l'import des bases EPSS et KEV
// (H3) : nombre de CVE, date d'import, date de la base publiée par le helper.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { intelStatus } from '../../intel/import'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return { feeds: await intelStatus(getPool()) }
})
