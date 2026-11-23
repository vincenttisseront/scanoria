// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/account : préférences de l'utilisateur connecté (langue, nom affiché).

import { defineEventHandler } from 'h3'
import { getPool } from '../utils/db'
import { clientAddress, readValidated, requireAuth } from '../utils/http'
import { writeAudit } from '../utils/audit'
import { updateUser } from '../utils/users'
import { accountUpdateSchema } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  const body = await readValidated(event, accountUpdateSchema)
  const pool = getPool()
  const user = await updateUser(pool, auth.user.id, body)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'account.update',
    outcome: 'success',
    targetType: 'user',
    targetId: String(auth.user.id),
    details: { fields: Object.keys(body) },
  })
  return { locale: user?.locale, display_name: user?.display_name ?? null }
})
