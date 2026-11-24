// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/restore (admin) : demande restore-module.
// Irréversible pour les données actuelles du module : la console exige une
// confirmation explicite (modale) et vérifie que la sauvegarde est listée dans
// l'état publié et faite avec la version installée. Le helper revérifie tout
// (empreintes, manifeste, version) sans faire confiance à la demande.

import { defineEventHandler } from 'h3'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { installedModuleParam } from '../../../../utils/catalog-actions'
import { moduleRestoreBodySchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const { id, installed } = await installedModuleParam(event)
  const body = await readValidated(event, moduleRestoreBodySchema)
  const backup = installed.backups?.find(b => b.id === body.backup)
  if (!backup) throw apiError(404, 'E_BACKUP_NOT_FOUND')
  if (backup.module_version !== installed.version) throw apiError(409, 'E_BACKUP_INVALID')
  return submitHelperAction(event, 'restore-module', { id, backup: backup.id }, {
    auditDetails: { version: installed.version, backup: backup.id, created_at: backup.created_at },
  })
})
