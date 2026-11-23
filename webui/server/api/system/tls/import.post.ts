// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/tls/import (admin) : demande import-certificate. La clé
// privée ne passe que dans le fichier de demande (0600, lu par root) ; elle
// n'est ni enregistrée en base, ni journalisée.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['import-certificate'])
  return submitHelperAction(event, 'import-certificate', params)
})
