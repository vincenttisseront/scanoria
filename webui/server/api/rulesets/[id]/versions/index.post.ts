// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/rulesets/:id/versions (admin) : nouvelle version (édition ou
// import). Une version n'est jamais modifiée.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../../../utils/db'
import { readValidated, requireRole } from '../../../../utils/http'
import { addRulesetVersion } from '../../../../rulesets/store'
import { mapRulesetError, rulesetActor } from '../../../../rulesets/http'

const body = z.strictObject({
  content: z.string().min(1).max(1024 * 1024),
  comment: z.string().max(2000).nullable().optional(),
  origin: z.enum(['manual', 'import']).default('manual'),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const b = await readValidated(event, body)
  try {
    const res = await withTransaction(getPool(), db => addRulesetVersion(db, {
      rulesetId: getRouterParam(event, 'id') ?? '', content: b.content, comment: b.comment ?? null, origin: b.origin, ...rulesetActor(event, auth),
    }))
    setResponseStatus(event, 201)
    return res
  }
  catch (err) {
    mapRulesetError(err)
  }
})
