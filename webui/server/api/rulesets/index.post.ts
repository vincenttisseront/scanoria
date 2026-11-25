// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/rulesets (admin) : crée un jeu de règles et sa première version
// (saisie ou import). Import Semgrep : l'administrateur reconnaît les
// conditions de la Semgrep Rules License (usage interne seulement, jamais
// redistribuées par l'appliance) ; la reconnaissance est tracée dans l'audit.

import { defineEventHandler, setResponseStatus } from 'h3'
import { z } from 'zod'
import { getPool, withTransaction } from '../../utils/db'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { addRulesetVersion, createRuleset, createRulesetSchema } from '../../rulesets/store'
import { mapRulesetError, rulesetActor } from '../../rulesets/http'

const body = createRulesetSchema.extend({
  content: z.string().min(1).max(1024 * 1024),
  comment: z.string().max(2000).nullable().optional(),
  origin: z.enum(['manual', 'import']).default('manual'),
  license_ack: z.boolean().optional(),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const b = await readValidated(event, body)
  if (b.engine === 'semgrep' && b.origin === 'import' && b.license_ack !== true) {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'license_ack', code: 'required' }] })
  }
  const actor = rulesetActor(event, auth)
  try {
    const res = await withTransaction(getPool(), async (db) => {
      const { id } = await createRuleset(db, { slug: b.slug, engine: b.engine, name: b.name, description: b.description ?? null, ...actor })
      const v = await addRulesetVersion(db, { rulesetId: id, content: b.content, comment: b.comment ?? null, origin: b.origin, ...actor })
      if (b.license_ack) {
        await writeAudit(db, {
          actor: { type: 'user', ...actor }, action: 'ruleset.license-ack', outcome: 'success', targetType: 'ruleset', targetId: id,
          details: { slug: b.slug, engine: b.engine, license: 'Semgrep Rules License' },
        })
      }
      return { id, ...v }
    })
    setResponseStatus(event, 201)
    return res
  }
  catch (err) {
    mapRulesetError(err)
  }
})
