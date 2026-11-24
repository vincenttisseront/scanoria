// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/components (viewer) : recherche transverse (F3) dans le dernier
// SBOM de chaque projet visible ; résultats groupés par projet, curseur.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { componentQuerySchema, searchComponents } from '../../sbom/search'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const q = queryValidated(event, componentQuerySchema)
  return searchComponents(getPool(), q, auth.user.role)
})
