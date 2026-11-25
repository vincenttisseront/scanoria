// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/mirror (admin) : déclare (ou retire) l'appliance
// miroir (F17). Action à risque confirmée dans une modale : le helper ouvre
// la sortie vers les seules adresses résolues du miroir, pour le seul compte
// de son client ; la clé attendue doit déjà être une clé de confiance.

import { defineEventHandler } from 'h3'
import { readValidated } from '../../../utils/http'
import { submitHelperAction } from '../../../utils/helper-actions'
import { requestParamSchemas } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const params = await readValidated(event, requestParamSchemas['set-mirror'])
  return submitHelperAction(event, 'set-mirror', params, {
    auditDetails: params.enabled ? { url: params.url, fingerprint: params.fingerprint, ca: !!params.ca_pem } : { enabled: false },
  })
})
