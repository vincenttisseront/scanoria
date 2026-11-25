// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings (viewer) : résultats unifiés, filtrés et paginés côté serveur.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { listFindings } from '../../findings/triage'
import { findingQuerySchema } from '../../findings/schemas'
import { ownerAliases } from '../../findings/owners'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const { mine, ...q } = queryValidated(event, findingQuerySchema)
  const pool = getPool()
  // F6 : « Mes résultats » = responsables reliés au compte connecté (jamais un autre compte).
  const me = mine ? { userId: auth.user.id, aliases: await ownerAliases(pool, auth.user.id) } : undefined
  return listFindings(pool, { ...q, mine: me })
})
