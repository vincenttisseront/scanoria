// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/components/export.csv (viewer) : la même recherche (F3), en CSV,
// une ligne par composant et par projet (au plus 20 000 lignes).

import { defineEventHandler, setHeader } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { componentQuerySchema, componentsCsv } from '../../sbom/search'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const q = queryValidated(event, componentQuerySchema)
  const csv = await componentsCsv(getPool(), q, auth.user.role)
  setHeader(event, 'Content-Type', 'text/csv; charset=utf-8')
  setHeader(event, 'Content-Disposition', 'attachment; filename="scanoria-composants.csv"')
  setHeader(event, 'Cache-Control', 'no-store')
  return csv
})
