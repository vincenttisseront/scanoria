// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// DELETE /api/triage-rules/:id (operator ; admin pour « accepted » et pour une
// règle de toute l'appliance) : révoque une règle de tri ; les résultats
// qu'elle avait triés et que personne n'a retouchés redeviennent « nouveaux ».

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, requireRole } from '../../utils/http'
import { revokeTriageRule, TriageRuleError } from '../../findings/triage-rules'
import { reevaluateProject } from '../../findings/exceptions'
import { uuidParam } from '../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  // Projets touchés lus avant l'annulation (triage_rule_id est remis à NULL).
  const projects = await pool.query<{ project_id: string }>('SELECT DISTINCT project_id FROM findings WHERE triage_rule_id = $1', [id])
  let out
  try {
    out = await withTransaction(pool, db => revokeTriageRule(db, id, { id: auth.user.id, username: auth.user.username, role: auth.user.role, ip: clientAddress(event) }))
  }
  catch (err) {
    if (err instanceof TriageRuleError) throw apiError(err.code === 'E_FORBIDDEN' ? 403 : 404, err.code === 'E_FORBIDDEN' ? 'E_FORBIDDEN' : 'E_NOT_FOUND')
    throw err
  }
  for (const p of projects.rows) await reevaluateProject(pool, p.project_id)
  return out
})
