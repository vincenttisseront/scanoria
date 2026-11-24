// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/update (admin) : demande update-module, vers la
// version indiquée ou, par défaut, la dernière de l'index. Le helper sauvegarde
// le module avant et revient en arrière si la santé échoue (§ 4.3).

import { defineEventHandler } from 'h3'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { compareVersions, findModule } from '../../../../utils/catalog'
import { moduleUpdateBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, installed, ctx } = await installedModuleParam(event)
  const body = await readValidated(event, moduleUpdateBodySchema)
  const target = findModule(ctx.index, id, body.version)
  if (!target) throw apiError(404, 'E_NOT_FOUND')
  if (compareVersions(target.version, installed.version) === 0) throw apiError(409, 'E_NO_UPDATE')
  return submitHelperAction(event, 'update-module', { id, version: target.version }, {
    auditDetails: { from_version: installed.version },
  })
})
