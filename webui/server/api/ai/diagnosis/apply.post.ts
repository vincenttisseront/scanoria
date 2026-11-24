// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/diagnosis/apply (operator) : applique, sur confirmation dans
// une modale, le réglage sûr proposé pour une analyse en échec (I15). La
// valeur est recalculée ici depuis les faits ; le corps ne porte que
// l'analyse et le délai affiché (refus 409 s'il a changé entre-temps).
// L'IA ne décide rien : c'est ce clic, tracé dans l'audit, qui applique.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { applyTimeoutProposal, timeoutProposal } from '../../../ai/console'

const Body = z.strictObject({
  scan_id: z.uuid(),
  module: z.string().regex(/^[a-z0-9][a-z0-9-]{1,40}$/),
  proposed_s: z.int().min(60).max(86_400),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const body = await readValidated(event, Body)
  const pool = getPool()
  const p = await timeoutProposal(pool, body.scan_id)
  if (!p) throw apiError(404, 'E_NOT_FOUND')
  if (p.module !== body.module || p.proposed_s !== body.proposed_s) throw apiError(409, 'E_AI_STALE')
  const overrides = await applyTimeoutProposal(pool, p, auth.user.id)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'ai.diagnosis.apply', outcome: 'success', targetType: 'scan', targetId: body.scan_id,
    details: { module: p.module, timeout_s: { from: p.current_s, to: p.proposed_s }, source: 'I15' },
  })
  return { module: p.module, timeout_s: p.proposed_s, overrides }
})
