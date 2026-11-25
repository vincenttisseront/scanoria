// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/profiles/preview (operator) : aperçu d'un profil avant
// enregistrement (G10). Lecture seule.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { getConfig } from '../../utils/config'
import { readValidated, requireRole } from '../../utils/http'
import { readCatalogIndex, readModulesState } from '../../utils/catalog'
import { readPlanCatalog } from '../../scans/plan'
import { previewProfile, profilePreviewSchema } from '../../profiles/preview'
import { profileHttpError } from '../../profiles/http'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const body = await readValidated(event, profilePreviewSchema)
  const cfg = getConfig()
  const [state, catalog, index] = await Promise.all([
    readModulesState(cfg.modulesStateFile), readPlanCatalog(cfg.catalogIndexFile), readCatalogIndex(cfg.catalogIndexFile),
  ])
  try {
    return await previewProfile(getPool(), body, { installed: state.modules, catalog, index })
  }
  catch (err) {
    profileHttpError(err)
  }
})
