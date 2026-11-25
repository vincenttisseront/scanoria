// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Validation d'un jeu de règles par son moteur (G4), jamais sur l'hôte : le
// contenu est déposé dans jobs/rulesets/<sha256>, puis une demande
// validate-ruleset est déposée au helper root, qui lance le module dans son
// conteneur confiné sur les exemples fournis. Validation asynchrone : la route
// rend l'identifiant de demande (202), la page suit GET /api/requests/:id.
// Résultat : { engine, module, version, ok, errors[], samples[{ name, matches }] }.
//
// Contrat donné au chantier F (I12) : testRuleset → submitRulesetTest (même
// entrée, samples ≤ 10 × 8 Kio { name, content }), puis lecture de la demande.

import type { H3Event } from 'h3'
import { z } from 'zod'
import { submitHelperAction } from '../utils/helper-actions'
import { apiError } from '../utils/http'
import { RULESET_ENGINES, sha256Hex, staticIssues, type RulesetEngine } from './store'
import { consoleScansDir, writeRulesetContent } from './files'

export const SAMPLE_NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/

export const rulesetTestSchema = z.strictObject({
  engine: z.enum(RULESET_ENGINES),
  content: z.string().min(1).max(1024 * 1024),
  samples: z.array(z.strictObject({
    name: z.string().regex(SAMPLE_NAME_RE),
    content: z.string().max(8192),
  })).max(10).refine(l => new Set(l.map(s => s.name)).size === l.length, 'duplicate').default([]),
  ruleset_id: z.uuid().optional(),
})
export type RulesetTestInput = z.infer<typeof rulesetTestSchema>

/** Dépose le contenu et la demande ; 400 si les contrôles statiques échouent déjà. */
export async function submitRulesetTest(event: H3Event, input: RulesetTestInput, scansDir = consoleScansDir()) {
  const issues = staticIssues(input.engine as RulesetEngine, input.content)
  if (issues.length) throw apiError(400, 'E_VALIDATION', { issues: issues.map(code => ({ path: 'content', code })) })
  const sha256 = sha256Hex(input.content)
  try {
    await writeRulesetContent(scansDir, sha256, input.content)
  }
  catch {
    throw apiError(503, 'E_UNAVAILABLE')
  }
  return submitHelperAction(event, 'validate-ruleset', {
    engine: input.engine, sha256, ...(input.samples.length ? { samples: input.samples } : {}),
  }, { dbContext: input.ruleset_id ? { ruleset_id: input.ruleset_id } : undefined, auditDetails: { sha256 } })
}
