// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ci/issuers (admin) : émetteurs OIDC de confiance (J4), avec le
// nombre de liaisons et la date du JWKS en cache, et les refus comptés depuis
// le démarrage (par raison). Jamais un jeton.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { listIssuers } from '../../ci/oidc'
import { oidcRefusalCounts } from '../../ci/auth'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  return { issuers: await listIssuers(getPool()), refusals: oidcRefusalCounts() }
})
