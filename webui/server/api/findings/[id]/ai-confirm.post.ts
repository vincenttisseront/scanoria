// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/ai-confirm (operator) : une personne confirme un
// résultat d'un module d'analyse par IA (0.7, contrat 32). Il devient un
// résultat normal et entre dans le verdict des analyses évaluées ensuite.
// Refusé à un compte non humain (users.kind « agent » ou « bot ») et à un
// jeton d'API : l'IA et les automates ne confirment jamais (CLAUDE.md § 3.5).
// Tracé dans l'audit (finding.ai-confirm).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { AiFindingError, confirmAiFinding, getAiFinding } from '../../../findings/ai-findings'
import { uuidParam } from '../../../findings/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    await withTransaction(pool, async (db) => {
      const before = await confirmAiFinding(db, id, auth.user.id)
      await writeAudit(db, {
        actor, action: 'finding.ai-confirm', outcome: 'success', targetType: 'finding', targetId: id,
        details: { project_id: before.project_id, module: before.tool },
      })
    })
  }
  catch (err) {
    if (err instanceof AiFindingError) {
      if (err.code === 'E_NOT_HUMAN') throw apiError(403, 'E_FORBIDDEN', { reason: 'not-human' })
      if (err.code === 'E_NOT_AI') throw apiError(409, 'E_NOT_AI')
      if (err.code === 'E_ALREADY_CONFIRMED') throw apiError(409, 'E_AI_CONFIRMED')
      throw apiError(404, 'E_NOT_FOUND')
    }
    throw err
  }
  return getAiFinding(pool, id)
})
