// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/rules/save (admin, personne humaine) : enregistre, sur
// confirmation dans une modale, la règle proposée par IA (I12) comme nouvelle
// version d'un jeu de règles G4, avec origin = 'ai'. Il faut une demande de
// test terminée et réussie (test_request_id) qui porte exactement cette règle
// et ces exemples ; sinon rien n'est enregistré. C'est ce clic, tracé dans
// l'audit, qui enregistre.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { RulegenError, SaveBody, saveRule } from '../../../ai/rulegen'
import { rulegenHttpError } from '../../../ai/rulegen-http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, SaveBody)
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  try {
    const r = await saveRule(pool, body, auth.user.id)
    await writeAudit(pool, {
      actor, action: 'ai.rule.save', outcome: 'success', targetType: 'ruleset', targetId: r.ruleset_id,
      details: {
        version: r.version, sha256: r.sha256, engine: r.engine, rule_id: r.rule_id, origin: 'ai', source: 'I12',
        model: r.model, model_digest: r.model_digest, task_id: r.task_id,
        test: { positive: r.verdict.positive_matches, negative: r.verdict.negative_matches },
      },
    })
    return r
  }
  catch (err) {
    if (err instanceof RulegenError && (err.reason === 'test-failed' || err.reason === 'not-human')) {
      await writeAudit(pool, {
        actor, action: 'ai.rule.save', outcome: err.reason === 'not-human' ? 'denied' : 'failure', targetType: 'rule',
        targetId: body.subject_id, details: { reason: err.reason, source: 'I12' },
      })
    }
    throw rulegenHttpError(err)
  }
})
