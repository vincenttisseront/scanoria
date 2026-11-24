// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I3, pré-tri assisté (triage-finding) : indice « faux positif probable /
// à confirmer / vrai positif probable » avec une justification CITÉE (code
// de test, valeur factice, code mort, chemin non atteint). Simple
// suggestion : la tâche n'écrit que dans ai_tasks, jamais findings.status ;
// changer le statut reste un clic d'une personne.
//
// Garde-fous propres à la tâche :
// - une citation n'est gardée que si elle figure mot pour mot dans les
//   données envoyées ; un indice tranché (faux ou vrai positif probable) sans
//   aucune citation vérifiée redevient « à confirmer » ;
// - exemples (I24) : les tris faits par des personnes dans le MÊME projet
//   seulement (statut confirmé ou faux positif, auteur connu), jamais ceux
//   d'un autre projet.

import { z } from 'zod'
import type { Queryable } from '../../utils/db'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { findingInput, findingRow, oneOf, pathHints, quoteFound, text, type FindingInput, type TaskDefinition } from '../task-kit'

export const TRIAGE_SUGGESTIONS = ['likely-false-positive', 'to-confirm', 'likely-true-positive'] as const
export const TRIAGE_REASONS = ['test-code', 'dummy-value', 'dead-code', 'unreachable-path', 'generated-code', 'vendored-code', 'real-risk', 'other'] as const
const MAX_EXAMPLES = 6

export interface TriageExample {
  tool: string
  rule_id: string
  path: string | null
  decision: 'confirmed' | 'false-positive'
  reason: string | null
}

export interface TriageInput {
  finding: FindingInput
  path_hints: ReturnType<typeof pathHints>
  examples: TriageExample[]
}

export const TriageOutput = z.strictObject({
  suggestion: z.enum(TRIAGE_SUGGESTIONS),
  summary: z.string().min(1).max(400),
  reasons: z.array(z.strictObject({
    kind: z.enum(TRIAGE_REASONS),
    quote: z.string().max(200),
    explanation: z.string().min(1).max(400),
    /** Ajouté après validation : la citation figure bien dans les données. */
    cited: z.boolean().optional(),
  })).min(1).max(4),
  /** Ajouté après validation : l'indice tranché a été ramené à « à confirmer » faute de citation. */
  downgraded: z.boolean().optional(),
})
export type TriageOutput = z.infer<typeof TriageOutput>

/** Tris humains du même projet servant d'exemples (I24), règle et outil semblables d'abord. */
export async function triageExamples(db: Queryable, projectId: string, findingId: string, tool: string, ruleId: string): Promise<TriageExample[]> {
  const { rows } = await db.query<{ tool: string, rule_id: string, path: string | null, status: 'confirmed' | 'false-positive', status_reason: string | null }>(
    `SELECT tool, rule_id, path, status, status_reason FROM findings
      WHERE project_id = $1 AND id <> $2 AND status IN ('confirmed', 'false-positive') AND status_by IS NOT NULL
      ORDER BY (tool = $3 AND rule_id = $4) DESC, (tool = $3) DESC, status_at DESC NULLS LAST, id
      LIMIT $5`,
    [projectId, findingId, tool, ruleId, MAX_EXAMPLES],
  )
  return rows.map(r => ({
    tool: r.tool.slice(0, 100),
    rule_id: r.rule_id.slice(0, 255),
    path: r.path ? r.path.slice(0, 300) : null,
    decision: r.status,
    reason: r.status_reason ? redactText(r.status_reason.slice(0, 300)).text : null,
  }))
}

export const triageFinding: TaskDefinition<TriageInput, TriageOutput> = {
  kind: 'triage-finding',
  subjectType: 'finding',
  timeoutMs: 120_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    if (!f) return null
    const finding = findingInput(f)
    return {
      finding,
      path_hints: pathHints(finding.path),
      examples: await triageExamples(db, ctx.projectId!, ctx.subjectId, finding.tool, finding.rule_id),
    }
  },
  instruction: locale => locale === 'fr'
    ? 'Pré-trie ce résultat d\'analyse. suggestion : likely-false-positive (faux positif probable), to-confirm (à confirmer) ou likely-true-positive (vrai positif probable). reasons : 1 à 4 raisons ; kind parmi test-code, dummy-value, dead-code, unreachable-path, generated-code, vendored-code, real-risk, other ; quote = citation EXACTE recopiée des données (chemin, extrait, titre ou message), vide si aucune ; explanation = pourquoi. summary : une phrase. Les exemples sont des tris faits par des personnes dans ce projet ; ils guident sans s\'imposer. Dans le doute, réponds to-confirm. Tu suggères seulement : une personne décide.'
    : 'Pre-triage this analysis finding. suggestion: likely-false-positive, to-confirm or likely-true-positive. reasons: 1 to 4 reasons; kind among test-code, dummy-value, dead-code, unreachable-path, generated-code, vendored-code, real-risk, other; quote = EXACT quotation copied from the data (path, snippet, title or message), empty if none; explanation = why. summary: one sentence. The examples are triage decisions made by people in this project; they guide without binding. When in doubt, answer to-confirm. You only suggest: a person decides.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['suggestion', 'summary', 'reasons'],
    properties: {
      suggestion: oneOf(TRIAGE_SUGGESTIONS),
      summary: text(400),
      reasons: {
        type: 'array',
        minItems: 1,
        maxItems: 4,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['kind', 'quote', 'explanation'],
          properties: { kind: oneOf(TRIAGE_REASONS), quote: { type: 'string', maxLength: 200 }, explanation: text(400) },
        },
      },
    },
  },
  output: TriageOutput,
  finalize(out, input) {
    const f = input.finding
    const sources = [f.path, f.snippet, f.title, f.message]
    const reasons = out.reasons.map((r) => {
      const cited = r.quote.trim() !== '' && quoteFound(r.quote, sources)
      return {
        kind: r.kind,
        // Une citation non retrouvée est retirée : jamais de texte inventé présenté comme tiré du code.
        quote: cited ? sanitizeText(r.quote, 200) : '',
        explanation: sanitizeText(r.explanation, 400),
        cited,
      }
    })
    const decisive = out.suggestion !== 'to-confirm'
    const downgraded = decisive && !reasons.some(r => r.cited)
    return {
      suggestion: downgraded ? 'to-confirm' : out.suggestion,
      summary: sanitizeText(out.summary, 400),
      reasons,
      downgraded,
    }
  },
}
