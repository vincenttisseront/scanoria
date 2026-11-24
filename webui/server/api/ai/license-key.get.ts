// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/license-key?license=&project_id= (viewer) : clé
// « licence|licence du projet » de l'explication d'une licence (I18), lue
// ensuite par /api/ai/output (kind explain-license). key null pour un projet
// « aucun envoi à l'IA » ou un identifiant hors de la forme SPDX.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireRole } from '../../utils/http'
import { LicenseKeyQuery, licenseKeyFor } from '../../ai/console-05'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, LicenseKeyQuery)
  const r = await licenseKeyFor(getPool(), q.license, q.project_id)
  if (!r.found) throw apiError(404, 'E_NOT_FOUND')
  return { key: r.key }
})
