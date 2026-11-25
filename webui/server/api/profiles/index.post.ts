// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/profiles (admin) : crée un profil personnalisé (catégories,
// modules, jeux de règles, parent, verrous). Un verrou hérité ne s'assouplit
// pas : 409 E_PROFILE_LOCKED avec la liste des règles en cause. Audit profile.create.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { createProfile, profileCreateSchema, syncAiOptOut } from '../../profiles/service'
import { profileHttpError } from '../../profiles/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, profileCreateSchema)
  try {
    const profile = await withTransaction(getPool(), async (client) => {
      const p = await createProfile(client, body, auth.user.id)
      await writeAudit(client, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'profile.create', outcome: 'success', targetType: 'profile', targetId: p.id,
        details: { slug: p.slug, level: p.level, parent: p.parent_slug, categories: p.categories, include_modules: p.include_modules, exclude_modules: p.exclude_modules, locks: p.locks },
      })
      await syncAiOptOut(client)
      return p
    })
    setResponseStatus(event, 201)
    return profile
  }
  catch (err) {
    profileHttpError(err)
  }
})
