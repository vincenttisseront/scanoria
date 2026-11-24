// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/backup (admin) : demande backup-module pour un
// module permanent (service ou runner). Le helper sauvegarde la base et les
// volumes déclarés (module arrêté le temps de la copie des volumes), écrit le
// manifeste et ses empreintes, et garde les 3 dernières sauvegardes (0.4).

import { defineEventHandler } from 'h3'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { moduleBackupBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, installed } = await installedModuleParam(event)
  await readValidated(event, moduleBackupBodySchema)
  if (installed.type !== 'service' && installed.type !== 'runner') throw apiError(409, 'E_NOT_PERMANENT')
  return submitHelperAction(event, 'backup-module', { id }, {
    auditDetails: { version: installed.version, backups_before: installed.backups?.length ?? 0 },
  })
})
