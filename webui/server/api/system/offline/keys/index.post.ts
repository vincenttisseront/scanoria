// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/keys (admin) : ajoute une clé de confiance des lots
// hors ligne. L'empreinte confirmée dans la modale doit être celle de la clé
// collée ; le helper la recalcule et refuse toute autre clé.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { apiError, readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { keyFingerprint } from '../../../../offline/status'
import { KEY_FINGERPRINT_RE, PUBLIC_KEY_B64_RE } from '#shared/schemas'

const body = z.strictObject({
  label: z.string().trim().min(1).max(100),
  public_key: z.string().trim().regex(PUBLIC_KEY_B64_RE),
  fingerprint: z.string().regex(KEY_FINGERPRINT_RE),
})

export default defineEventHandler(async (event) => {
  const b = await readValidated(event, body)
  if (keyFingerprint(b.public_key) !== b.fingerprint) throw apiError(400, 'E_VALIDATION', { field: 'fingerprint' })
  return submitHelperAction(event, 'trust-key', { action: 'add', public_key: b.public_key, fingerprint: b.fingerprint }, {
    dbContext: { label: b.label },
    auditDetails: { label: b.label, fingerprint: b.fingerprint },
  })
})
