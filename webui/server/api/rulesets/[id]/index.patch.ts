// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/rulesets/:id (admin) : nom, description, archivage. Un jeu
// archivé n'est plus monté dans aucune analyse ; il faut d'abord le détacher
// de ses profils.

import { defineEventHandler, getRouterParam } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, readValidated, requireRole } from '../../../utils/http'
import { getRuleset, listAttachments, setArchived, updateRulesetMeta } from '../../../rulesets/store'
import { mapRulesetError, rulesetActor } from '../../../rulesets/http'

const body = z.strictObject({
  name: z.string().trim().min(1).max(200).optional(),
  description: z.string().max(2000).nullable().optional(),
  archived: z.boolean().optional(),
}).refine(b => Object.keys(b).length > 0, 'empty')

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const b = await readValidated(event, body)
  const actor = rulesetActor(event, auth)
  try {
    return await withTransaction(getPool(), async (db) => {
      const rs = await getRuleset(db, getRouterParam(event, 'id') ?? '')
      if (!rs) throw apiError(404, 'E_NOT_FOUND')
      if (b.name !== undefined || b.description !== undefined) {
        await updateRulesetMeta(db, { rulesetId: rs.id, name: b.name, description: b.description, ...actor })
      }
      if (b.archived !== undefined && b.archived !== (rs.archived_at !== null)) {
        if (b.archived && (await listAttachments(db, rs.id)).length) throw apiError(409, 'E_PRECONDITION', { reason: 'attached' })
        await setArchived(db, { rulesetId: rs.id, archived: b.archived, ...actor })
      }
      return { ruleset: await getRuleset(db, rs.id) }
    })
  }
  catch (err) {
    mapRulesetError(err)
  }
})
