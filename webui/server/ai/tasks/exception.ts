// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I10, rédaction des exceptions (draft-exception) : pour un résultat dont une
// personne s'apprête à demander une exception (F5, J15), motif rédigé à
// partir du contexte MASQUÉ du résultat et durée proposée. Depuis la 0.8
// (H7), pour une vulnérabilité de dépendance : statut VEX et justification
// OpenVEX proposés, appuyés sur l'avis d'atteignabilité I11 quand il existe
// (jamais pour un autre résultat : vex_status null).
//
// Une proposition seulement : la tâche n'écrit que dans ai_tasks. Le motif
// est recopié dans le formulaire de demande, où l'opérateur le relit, le
// corrige et le soumet lui-même ; l'administrateur approuve comme d'habitude.
// Rien n'est jamais soumis automatiquement (CLAUDE.md § 3.5 : l'IA ne crée
// ni n'approuve d'exception). Aucune rédaction pour un résultat malveillant
// (H4 : aucune exception possible) ; pour un secret, ni valeur, ni message,
// ni extrait (findingInput).

import { z } from 'zod'
import { sanitizeText } from '../sanitize'
import { findingInput, findingRow, oneOf, pathHints, text, type FindingInput, type TaskDefinition } from '../task-kit'
import { VEX_JUSTIFICATIONS, VEX_STATUSES } from '../../vex/format'
import { ReachOutput } from './reach'

/** Durées bornées comme une exception : au plus 366 jours ; la proposition est ramenée dans [7, 366]. */
export const DRAFT_MIN_DAYS = 7
export const DRAFT_MAX_DAYS = 366

export interface DraftExceptionInput {
  finding: FindingInput
  path_hints: ReturnType<typeof pathHints>
  max_days: number
  /** H7 (0.8) : vulnérabilité de dépendance, pour laquelle un statut VEX a un sens. */
  vex_applicable?: boolean
  /** I11 : dernier avis d'atteignabilité du résultat (sans emplacement ni extrait). */
  reachability?: { reachability: string, summary: string } | null
}

/** Catégories dont les résultats portent des vulnérabilités de dépendances. */
const VEX_CATEGORIES = ['sca', 'container', 'sbom']
const NONE = 'none'

export const DraftExceptionOutput = z.strictObject({
  reason: z.string().min(1).max(1500),
  expires_in_days: z.number().int().min(1).max(DRAFT_MAX_DAYS),
  duration_rationale: z.string().min(1).max(400),
  /** À vérifier par la personne avant de soumettre (conditions, compensations). */
  to_check: z.array(z.string().min(1).max(300)).max(5),
  /** H7 (0.8) : statut VEX proposé ; « none » du modèle et résultat sans vulnérabilité donnent null. */
  vex_status: z.enum([...VEX_STATUSES, NONE]).nullable().optional(),
  vex_justification: z.enum([...VEX_JUSTIFICATIONS, NONE]).nullable().optional(),
})
export type DraftExceptionOutput = z.infer<typeof DraftExceptionOutput>

export const draftException: TaskDefinition<DraftExceptionInput, DraftExceptionOutput> = {
  kind: 'draft-exception',
  subjectType: 'finding',
  timeoutMs: 120_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    if (!f || f.malicious === true) return null
    const finding = findingInput(f)
    const vexApplicable = finding.vuln_ids.length > 0 && VEX_CATEGORIES.includes(finding.category)
    return { finding, path_hints: pathHints(finding.path), max_days: DRAFT_MAX_DAYS, vex_applicable: vexApplicable, reachability: vexApplicable ? await reachOf(db, ctx) : null }
  },
  instruction: locale => locale === 'fr'
    ? 'Une personne va DEMANDER une exception pour ce résultat d\'analyse ; un administrateur décidera. Propose : reason (motif factuel de 2 à 5 phrases : pourquoi le risque est acceptable ou non applicable ici, mesures compensatoires éventuelles, ce qui permettra de lever l\'exception ; n\'affirme rien que les données ne montrent pas), expires_in_days (durée courte et justifiée, au plus max_days ; 30 à 90 jours pour un risque réel en attente de correction), duration_rationale (une phrase), to_check (points que la personne doit vérifier avant de soumettre). Si vex_applicable est vrai, propose aussi vex_status (not_affected, affected, fixed ou under_investigation) et vex_justification (justification OpenVEX, seulement pour not_affected), en t\'appuyant sur reachability quand il est fourni ; sinon « none » pour les deux. Tu proposes seulement : tu ne décides rien.'
    : 'A person is about to REQUEST an exception for this analysis finding; an administrator will decide. Propose: reason (factual rationale of 2 to 5 sentences: why the risk is acceptable or not applicable here, any compensating measures, what will allow the exception to be lifted; do not claim anything the data does not show), expires_in_days (short and justified duration, at most max_days; 30 to 90 days for a real risk awaiting a fix), duration_rationale (one sentence), to_check (points the person must check before submitting). If vex_applicable is true, also propose vex_status (not_affected, affected, fixed or under_investigation) and vex_justification (OpenVEX justification, only for not_affected), relying on reachability when provided; otherwise "none" for both. You only propose: you decide nothing.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['reason', 'expires_in_days', 'duration_rationale', 'to_check', 'vex_status', 'vex_justification'],
    properties: {
      reason: text(1500),
      expires_in_days: { type: 'integer', minimum: 1, maximum: DRAFT_MAX_DAYS },
      duration_rationale: text(400),
      to_check: { type: 'array', maxItems: 5, items: text(300) },
      vex_status: oneOf([...VEX_STATUSES, NONE]),
      vex_justification: oneOf([...VEX_JUSTIFICATIONS, NONE]),
    },
  },
  output: DraftExceptionOutput,
  finalize: (out, input) => {
    const status = input.vex_applicable && out.vex_status && out.vex_status !== NONE ? out.vex_status : null
    const justification = status === 'not_affected' && out.vex_justification && out.vex_justification !== NONE ? out.vex_justification : null
    return {
      reason: sanitizeText(out.reason, 1500),
      expires_in_days: Math.min(DRAFT_MAX_DAYS, Math.max(DRAFT_MIN_DAYS, Math.round(out.expires_in_days))),
      duration_rationale: sanitizeText(out.duration_rationale, 400),
      to_check: out.to_check.map(s => sanitizeText(s, 300)),
      vex_status: status,
      vex_justification: justification,
    }
  },
}

/** I11 : dernier avis d'atteignabilité terminé du résultat, dans le même projet ; seulement le verdict et son résumé. */
async function reachOf(db: Parameters<DraftExceptionDefinition['load']>[0], ctx: Parameters<DraftExceptionDefinition['load']>[1]): Promise<{ reachability: string, summary: string } | null> {
  const r = await db.query<{ output: unknown }>(
    `SELECT output FROM ai_tasks WHERE kind = 'assess-reachability' AND subject_id = $1 AND project_id = $2 AND status = 'done'
      ORDER BY finished_at DESC NULLS LAST LIMIT 1`, [ctx.subjectId, ctx.projectId])
  const parsed = ReachOutput.safeParse(r.rows[0]?.output)
  return parsed.success ? { reachability: parsed.data.reachability, summary: sanitizeText(parsed.data.summary, 800) } : null
}
type DraftExceptionDefinition = TaskDefinition<DraftExceptionInput, DraftExceptionOutput>
