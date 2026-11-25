// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/config/import/apply (admin) {yaml, digest} : applique une
// configuration prévisualisée (même empreinte), en une transaction, avec les
// règles habituelles de la console (verrous G8, H4, G13). Audit config.import.

import { createError, defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { APPLIANCE_CONFIG_MAX_BYTES, ImportError, applyImport } from '../../../config/appliance'

const body = z.strictObject({ yaml: z.string().min(1).max(APPLIANCE_CONFIG_MAX_BYTES), digest: z.string().regex(/^[0-9a-f]{64}$/) })

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const { yaml, digest } = await readValidated(event, body)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    return await withTransaction(getPool(), async (client) => {
      const preview = await applyImport(client, yaml, digest, auth.user.id)
      await writeAudit(client, {
        actor, action: 'config.import', outcome: 'success', targetType: 'config',
        details: { digest, summary: preview.summary, changes: preview.changes.filter(c => c.action !== 'unchanged').slice(0, 500) },
      })
      return preview
    })
  }
  catch (err) {
    if (err instanceof ImportError) {
      await writeAudit(getPool(), { actor, action: 'config.import', outcome: 'failure', targetType: 'config', details: { digest, code: err.code, issues: err.issues.slice(0, 20) } })
      throw createError({ statusCode: err.code === 'E_CONFIG_DIGEST' ? 409 : 422, statusMessage: err.code, data: { code: err.code, issues: err.issues } })
    }
    throw err
  }
})
