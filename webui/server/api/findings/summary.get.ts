// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings/summary (viewer) : résultats ouverts par projet et par
// gravité, secrets à révoquer (relance F7), paquets malveillants (H4).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { findingsSummary } from '../../findings/triage'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return { projects: await findingsSummary(getPool()) }
})
