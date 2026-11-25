// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/profiles/:id/archive (admin) {archived} : archive ou restaure un
// profil. Jamais un profil intégré, ni un profil utilisé par un projet ou
// parent d'un profil actif. Audit profile.archive.

import { defineEventHandler, getRouterParam } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { uuidParam } from '../../../gates/http'
import { archiveProfile } from '../../../profiles/service'
import { profileHttpError } from '../../../profiles/http'

const body = z.strictObject({ archived: z.boolean() })

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const { archived } = await readValidated(event, body)
  try {
    return await withTransaction(getPool(), async (client) => {
      const p = await archiveProfile(client, id, archived, auth.user.id)
      await writeAudit(client, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'profile.archive', outcome: 'success', targetType: 'profile', targetId: id,
        details: { slug: p.slug, archived },
      })
      return p
    })
  }
  catch (err) {
    profileHttpError(err)
  }
})
