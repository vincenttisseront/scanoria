// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/severity-maps (viewer) : normalisation des gravités par module
// (G5), avec la valeur d'origine (manifeste, sinon règle par défaut).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'
import { listSeverityMaps } from '../../findings/severity'
import { readModuleHints } from '../../findings/manifest'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  return { items: await listSeverityMaps(getPool(), async id => (await readModuleHints(id)).severityMap) }
})
