// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/rulesets/:id/profiles (admin) : profils qui montent ce jeu de
// règles, chacun sur une version épinglée ou sur la dernière (null).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { attachmentsSchema, listAttachments, setAttachments } from '../../../rulesets/store'
import { mapRulesetError, rulesetActor } from '../../../rulesets/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const b = await readValidated(event, attachmentsSchema)
  const id = getRouterParam(event, 'id') ?? ''
  try {
    return await withTransaction(getPool(), async (db) => {
      await setAttachments(db, { rulesetId: id, profiles: b.profiles, ...rulesetActor(event, auth) })
      return { attachments: await listAttachments(db, id) }
    })
  }
  catch (err) {
    mapRulesetError(err)
  }
})
