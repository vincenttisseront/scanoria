// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/admin-password (admin) : demande
// reset-service-admin, pour un module dont l'appliance gère le compte
// administrateur (SonarQube). Le mot de passe se lit ensuite une seule fois
// par POST /api/catalog/modules/:id/admin-password/reveal.

import { defineEventHandler } from 'h3'
import { apiError } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { managesAdmin } from '../../../../services/admin-access'

export default defineEventHandler(async (event) => {
  const { id } = await installedModuleParam(event)
  if (!managesAdmin(id)) throw apiError(409, 'E_PRECONDITION')
  return submitHelperAction(event, 'reset-service-admin', { id })
})
