// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/rulesets/:id/versions/:version : contenu d'une version ;
// ?diff=<autre version> rend en plus la différence ligne à ligne.

import { defineEventHandler, getRouterParam } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../../utils/db'
import { apiError, queryValidated, requireRole } from '../../../../utils/http'
import { getVersionContent, lineDiff } from '../../../../rulesets/store'

const query = z.object({ diff: z.coerce.number().int().min(1).optional() })
const version = z.coerce.number().int().min(1).max(1_000_000)

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const q = queryValidated(event, query)
  const id = getRouterParam(event, 'id') ?? ''
  const v = version.safeParse(getRouterParam(event, 'version'))
  if (!v.success || !z.uuid().safeParse(id).success) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const cur = await getVersionContent(pool, id, v.data)
  if (!cur) throw apiError(404, 'E_NOT_FOUND')
  if (q.diff === undefined) return { version: v.data, ...cur }
  const other = await getVersionContent(pool, id, q.diff)
  if (!other) throw apiError(404, 'E_NOT_FOUND')
  return { version: v.data, ...cur, diff_from: q.diff, diff: lineDiff(other.content, cur.content) }
})
