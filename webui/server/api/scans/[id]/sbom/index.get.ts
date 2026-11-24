// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/sbom (viewer) : composants du SBOM de l'analyse (contrat
// 14 de la 0.5), filtrés (texte, écosystème, licence, direct), triés et
// paginés ; facettes, couverture (G15) et lien vers Dependency-Track.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { queryValidated, requireRole } from '../../../../utils/http'
import { scanError, scanIdParam } from '../../../../scans/api'
import { sbomPage, sbomQuery, scanForSbom } from '../../../../sbom/api'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const query = queryValidated(event, sbomQuery)
  const scan = await scanForSbom(getPool(), scanIdParam(getRouterParam(event, 'id')))
  if (!scan) throw scanError(404, 'E_SCAN_NOT_FOUND')
  return sbomPage(getPool(), scan, query)
})
