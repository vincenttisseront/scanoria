// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/system/offline/keys/remove (admin) : retire une clé de confiance
// (confirmée dans une modale). Les lots qu'elle a signés ne s'importent plus ;
// la ligne reste en base avec revoked_at, pour l'audit.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { readValidated } from '../../../../utils/http'
import { submitHelperAction } from '../../../../utils/helper-actions'
import { KEY_FINGERPRINT_RE } from '#shared/schemas'

const body = z.strictObject({ fingerprint: z.string().regex(KEY_FINGERPRINT_RE) })

export default defineEventHandler(async (event) => {
  const { fingerprint } = await readValidated(event, body)
  return submitHelperAction(event, 'trust-key', { action: 'remove', fingerprint }, { auditDetails: { fingerprint } })
})
