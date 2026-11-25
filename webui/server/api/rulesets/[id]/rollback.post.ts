// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/rulesets/:id/rollback (admin) : retour à une version antérieure,
// qui crée une nouvelle version au même contenu (l'historique est conservé).

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../../utils/db'
import { readValidated, requireRole } from '../../../utils/http'
import { rollbackRuleset } from '../../../rulesets/store'
import { mapRulesetError, rulesetActor } from '../../../rulesets/http'

const body = z.strictObject({ version: z.number().int().min(1) })

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const b = await readValidated(event, body)
  try {
    const res = await withTransaction(getPool(), db => rollbackRuleset(db, {
      rulesetId: getRouterParam(event, 'id') ?? '', version: b.version, ...rulesetActor(event, auth),
    }))
    setResponseStatus(event, 201)
    return res
  }
  catch (err) {
    mapRulesetError(err)
  }
})
