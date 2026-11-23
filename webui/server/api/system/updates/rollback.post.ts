// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/updates/rollback (admin) : demande rollback-update (N-1).
// La base est restaurée depuis la sauvegarde prise avant la mise à jour :
// les données écrites depuis sont perdues (annoncé par la modale).

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['rollback-update'])
  return submitHelperAction(event, 'rollback-update', params)
})
