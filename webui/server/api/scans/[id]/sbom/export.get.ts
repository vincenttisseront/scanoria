// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/sbom/export (viewer) : SBOM de l'analyse en CycloneDX 1.6
// (JSON), régénéré depuis sbom_components (forme durable du SBOM, contrat 14),
// en fichier téléchargeable. Audité.

import { defineEventHandler, getRouterParam, setHeader } from 'h3'
import { getPool } from '../../../../utils/db'
import { requireRole } from '../../../../utils/http'
import { auditScanAction, scanError, scanIdParam } from '../../../../scans/api'
import { scanForSbom } from '../../../../sbom/api'
import { sbomDocument, scanSbom } from '../../../../sbom/ingest'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const scan = await scanForSbom(getPool(), scanIdParam(getRouterParam(event, 'id')))
  if (!scan) throw scanError(404, 'E_SCAN_NOT_FOUND')
  const rows = await scanSbom(getPool(), scan.id)
  if (!rows.length) throw scanError(404, 'E_SCAN_NOT_FOUND')
  await auditScanAction(event, auth, 'scan.sbom-export', scan.id, 'success', { components: rows.length })
  setHeader(event, 'content-type', 'application/vnd.cyclonedx+json; charset=utf-8')
  setHeader(event, 'content-disposition', `attachment; filename="${scan.project_slug}-${scan.number}.cdx.json"`)
  setHeader(event, 'cache-control', 'no-store')
  return JSON.stringify(sbomDocument(rows, { scanId: scan.id, project: scan.project_name, createdAt: scan.finished_at }))
})
