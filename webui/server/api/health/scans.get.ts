// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/health/scans (lecteur) : santé des analyses par outil sur 7 et
// 30 jours (G20) et analyses récentes dont un module a échoué.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireAuth } from '../../utils/http'
import { scanHealth } from '../../health/scans'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  return scanHealth(getPool())
})
