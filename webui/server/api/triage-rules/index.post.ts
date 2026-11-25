// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/triage-rules (operator ; admin pour « accepted » et pour une règle
// de toute l'appliance) : enregistre une règle de tri en masse (F4) et
// l'applique aussitôt aux résultats nouveaux qu'elle couvre. Justification et
// date de fin obligatoires. Une règle « accepted » vaut une exception
// approuvée : le verdict des dernières analyses des projets touchés est
// recalculé sans réanalyse. Auditée (une ligne par résultat, ou synthèse).

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { createTriageRule, triageRuleSchema, TriageRuleError } from '../../findings/triage-rules'
import { reevaluateProject } from '../../findings/exceptions'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, triageRuleSchema)
  const pool = getPool()
  const ip = clientAddress(event)
  let out
  try {
    out = await withTransaction(pool, db => createTriageRule(db, body, { id: auth.user.id, username: auth.user.username, role: auth.user.role, ip }))
  }
  catch (err) {
    if (err instanceof TriageRuleError) {
      if (err.code === 'E_FORBIDDEN') {
        await writeAudit(pool, { actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip }, action: 'triage-rule.create', outcome: 'denied', targetType: 'project', targetId: body.project_id, details: { action: body.action } })
        throw apiError(403, 'E_FORBIDDEN')
      }
      if (err.code === 'E_NOT_FOUND') throw apiError(404, 'E_NOT_FOUND')
      throw apiError(400, 'E_VALIDATION', { issues: [{ path: err.detail ?? '', code: 'out_of_range' }] })
    }
    throw err
  }
  // Un statut posé en masse change le verdict comme un tri à la main : statuts de forge republiés.
  const projects = await pool.query<{ project_id: string }>('SELECT DISTINCT project_id FROM findings WHERE triage_rule_id = $1', [out.rule.id])
  for (const p of projects.rows) await reevaluateProject(pool, p.project_id)
  setResponseStatus(event, 201)
  return out
})
