// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/gates/:id (admin) : nouvelles règles (GateRules ; H4 et G13 ne
// peuvent pas être désactivés). Audit gate.update avec l'avant et l'après.
// I19 (0.8) : ai_task_id désigne la proposition de l'IA d'où viennent les
// règles ; l'audit garde « proposé par IA » (tâche, modèle, empreinte, et si
// la personne a modifié la proposition). L'enregistrement reste ce clic.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { gateUpdateSchema, getGate, updateGateRules } from '../../../gates/gates'
import { uuidParam } from '../../../gates/http'
import { suggestionByTask } from '../../../gates/suggest'
import { canonicalJson } from '../../../vex/format'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, gateUpdateSchema)
  let proposedByAi: Record<string, unknown> | null = null
  if (body.ai_task_id) {
    const s = await suggestionByTask(getPool(), body.ai_task_id)
    if (!s || s.gate_id !== id) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'ai_task_id', code: 'invalid' }] })
    proposedByAi = {
      task_id: s.task_id, project_id: s.project_id, model: s.model, model_digest: s.model_digest,
      modified: canonicalJson(s.rules) !== canonicalJson(body.rules),
    }
  }
  return withTransaction(getPool(), async (client) => {
    const before = await getGate(client, id)
    if (!before) throw apiError(404, 'E_NOT_FOUND')
    const after = await updateGateRules(client, id, body.rules, auth.user.id)
    const changes: Record<string, { from: unknown, to: unknown }> = {}
    for (const [k, v] of Object.entries(body.rules)) {
      const old = (before.rules as Record<string, unknown>)[k]
      if (old !== v) changes[k] = { from: old ?? null, to: v }
    }
    await writeAudit(client, {
      actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
      action: 'gate.update', outcome: 'success', targetType: 'gate', targetId: id,
      details: { slug: before.slug, changes, ...(proposedByAi ? { proposed_by_ai: proposedByAi } : {}) },
    })
    return after
  })
})
