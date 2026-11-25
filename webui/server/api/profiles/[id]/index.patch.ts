// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/profiles/:id (admin) : modifie un profil. Refus clair si la
// modification assouplit un verrou hérité, si un descendant assouplirait le
// nouveau verrou, ou si la hiérarchie devient invalide. Audit profile.update
// avec l'avant et l'après.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { uuidParam } from '../../../gates/http'
import { profileUpdateSchema, syncAiOptOut, updateProfile } from '../../../profiles/service'
import { profileHttpError } from '../../../profiles/http'

const FIELDS = ['level', 'parent_id', 'categories', 'include_modules', 'exclude_modules', 'description', 'locks', 'rulesets'] as const

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, profileUpdateSchema)
  try {
    const { after, locked } = await withTransaction(getPool(), async (client) => {
      const { before, after } = await updateProfile(client, id, body, auth.user.id)
      const changes: Record<string, { from: unknown, to: unknown }> = {}
      for (const k of FIELDS) {
        if (body[k] === undefined) continue
        const from = (before as unknown as Record<string, unknown>)[k]
        const to = (after as unknown as Record<string, unknown>)[k]
        if (JSON.stringify(from) !== JSON.stringify(to)) changes[k] = { from: from ?? null, to: to ?? null }
      }
      const locked = await syncAiOptOut(client)
      await writeAudit(client, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'profile.update', outcome: 'success', targetType: 'profile', targetId: id,
        details: { slug: before.slug, changes, ai_opt_out_imposed: locked.map(p => p.slug) },
      })
      return { after, locked }
    })
    return { ...after, ai_opt_out_imposed: locked.map(p => p.slug) }
  }
  catch (err) {
    profileHttpError(err)
  }
})
