// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/releases/:scanId (viewer) : page Release d'une analyse : verdict,
// rapport (signé, en attente ou en erreur), comparaison F2 avec la release
// précédente, statut scanoria/release-gate et fichiers publiés dans la forge.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { uuidParam } from '../../../gates/http'
import { releaseError, releaseView } from '../../../release/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const view = await releaseView(getPool(), uuidParam(getRouterParam(event, 'scanId')))
  if (!view) throw releaseError(404, 'E_RELEASE_NOT_FOUND')
  return view
})
