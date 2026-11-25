// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I19, seuils de quality gate suggérés (suggest-gate) : à partir de
// l'historique d'un projet, l'IA propose des seuils de départ et des
// exceptions candidates, puis la proposition passe AUTOMATIQUEMENT dans le
// simulateur F9 (origin « ai », server/gates/suggest.ts) pour en montrer
// l'effet.
// - Sujet « gate », identifiant = le projet. Seules des MÉTADONNÉES partent
//   (CLAUDE.md § 3.5, cloisonnement) : règles actuelles, comptes de verdicts
//   et de raisons, et par règle d'outil : outil, identifiant de règle,
//   catégorie, gravité, nombre. Jamais un chemin, un message, un extrait ni
//   rien d'un autre projet. Rien pour un projet « aucun envoi à l'IA ».
// - L'IA ne touche qu'aux seuils (nouveau code seulement, secrets tolérés,
//   gravités bloquantes des vulnérabilités, du SAST et de l'IaC), qu'elle peut
//   relever ou assouplir : la simulation montre l'effet et l'interface signale
//   chaque assouplissement. H4, G13, KEV, EPSS, licences, quarantaine et
//   fraîcheur restent ceux du gate, et le plancher verrouillé d'un profil (G8)
//   s'applique toujours à l'évaluation.
// - Les exceptions candidates ne visent que des règles vues dans l'historique,
//   jamais un avis malveillant (MAL-, H4). Elles sont affichées, pas créées :
//   une personne les demande elle-même (F5).
// - Enregistrer les règles reste un clic humain (PATCH /api/gates/:id, audité
//   avec la mention « proposé par IA »).

import { z } from 'zod'
import { GateRules, SEVERITIES } from '#shared/analysis'
import { sanitizeText } from '../sanitize'
import { oneOf, text, UUID_RE, type TaskDefinition } from '../task-kit'
import type { Queryable } from '../../utils/db'

export const SUGGEST_WINDOW_DAYS = 90
const MAX_RULES = 40
const MAX_EXCEPTIONS = 8
const NONE = 'none'
const SEVERITY_OR_NONE = [...SEVERITIES, NONE] as const
/** Forme d'un identifiant d'outil ou de règle repris dans une exception candidate (aucun espace : rien d'une consigne). */
const IDENT_RE = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}$/

/** Règles que l'IA peut proposer ; toutes les autres restent celles du gate. */
export const SUGGESTED_KEYS = ['new_code_only', 'max_secrets', 'vuln_block_from', 'sast_block_from', 'iac_block_from'] as const

export interface SuggestGateInput {
  window_days: number
  current_rules: Pick<GateRules, (typeof SUGGESTED_KEYS)[number]>
  scans: { total: number, passed: number, failed: number, inconclusive: number, releases: number, releases_blocked: number }
  /** Raisons bloquantes vues dans les verdicts : code et nombre d'analyses. */
  blocking_reasons: { code: string, scans: number }[]
  /** Règles d'outil les plus fréquentes dans les résultats de la période. */
  rules: { tool: string, rule_id: string, category: string, severity: string, findings: number, scans: number }[]
}

const SuggestedRules = z.strictObject({
  new_code_only: z.boolean(),
  max_secrets: z.number().int().min(0).max(50),
  vuln_block_from: z.enum(SEVERITY_OR_NONE),
  sast_block_from: z.enum(SEVERITY_OR_NONE),
  iac_block_from: z.enum(SEVERITY_OR_NONE),
})

export const SuggestGateOutput = z.strictObject({
  rules: SuggestedRules,
  rationale: z.string().min(1).max(1500),
  exceptions: z.array(z.strictObject({
    tool: z.string().min(1).max(100),
    rule_id: z.string().min(1).max(255),
    reason: z.string().min(1).max(500),
    expires_in_days: z.number().int().min(7).max(366),
  })).max(MAX_EXCEPTIONS),
})
export type SuggestGateOutput = z.infer<typeof SuggestGateOutput>

/** Règles candidates complètes : règles actuelles du gate, seuils remplacés par la proposition. */
export function mergeSuggestedRules(current: unknown, suggested: SuggestGateOutput['rules']): GateRules {
  const base = GateRules.parse(current ?? {})
  const sev = (v: string) => (v === NONE ? null : v)
  return GateRules.parse({
    ...base,
    new_code_only: suggested.new_code_only,
    max_secrets: suggested.max_secrets,
    vuln_block_from: sev(suggested.vuln_block_from),
    sast_block_from: sev(suggested.sast_block_from),
    iac_block_from: sev(suggested.iac_block_from),
  })
}

async function loadInput(db: Queryable, projectId: string): Promise<SuggestGateInput | null> {
  const p = await db.query<{ rules: unknown }>(
    'SELECT g.rules FROM projects p JOIN gates g ON g.id = p.gate_id WHERE p.id = $1', [projectId])
  if (!p.rows[0]) return null
  const rules = GateRules.parse(p.rows[0].rules)
  const since = `now() - interval '${SUGGEST_WINDOW_DAYS} days'`
  const [scans, reasons, top] = await Promise.all([
    db.query<SuggestGateInput['scans']>(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE verdict = 'passed')::int AS passed,
              count(*) FILTER (WHERE verdict = 'failed')::int AS failed,
              count(*) FILTER (WHERE verdict = 'inconclusive')::int AS inconclusive,
              count(*) FILTER (WHERE trigger = 'release')::int AS releases,
              count(*) FILTER (WHERE trigger = 'release' AND verdict <> 'passed')::int AS releases_blocked
         FROM scans WHERE project_id = $1 AND status = 'done' AND verdict IS NOT NULL AND finished_at >= ${since}`, [projectId]),
    db.query<{ code: string, scans: number }>(
      `SELECT r->>'code' AS code, count(DISTINCT s.id)::int AS scans
         FROM scans s, jsonb_array_elements(CASE WHEN jsonb_typeof(s.verdict_details->'reasons') = 'array' THEN s.verdict_details->'reasons' ELSE '[]'::jsonb END) r
        WHERE s.project_id = $1 AND s.status = 'done' AND s.finished_at >= ${since} AND (r->>'blocking')::boolean IS TRUE
        GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 20`, [projectId]),
    db.query<SuggestGateInput['rules'][number]>(
      `SELECT f.tool, f.rule_id, f.category, f.severity, count(DISTINCT f.id)::int AS findings, count(DISTINCT sf.scan_id)::int AS scans
         FROM scan_findings sf JOIN scans s ON s.id = sf.scan_id JOIN findings f ON f.id = sf.finding_id
        WHERE s.project_id = $1 AND f.project_id = $1 AND s.status = 'done' AND s.finished_at >= ${since}
        GROUP BY 1, 2, 3, 4 ORDER BY 5 DESC, 1, 2 LIMIT ${MAX_RULES}`, [projectId]),
  ])
  return {
    window_days: SUGGEST_WINDOW_DAYS,
    current_rules: Object.fromEntries(SUGGESTED_KEYS.map(k => [k, rules[k]])) as SuggestGateInput['current_rules'],
    scans: scans.rows[0] ?? { total: 0, passed: 0, failed: 0, inconclusive: 0, releases: 0, releases_blocked: 0 },
    blocking_reasons: reasons.rows.map(r => ({ code: String(r.code).slice(0, 40), scans: r.scans })),
    rules: top.rows.map(r => ({
      tool: String(r.tool).slice(0, 100), rule_id: String(r.rule_id).slice(0, 255), category: String(r.category).slice(0, 40),
      severity: String(r.severity), findings: r.findings, scans: r.scans,
    })),
  }
}

export const suggestGate: TaskDefinition<SuggestGateInput, SuggestGateOutput> = {
  kind: 'suggest-gate',
  subjectType: 'gate',
  timeoutMs: 180_000,
  async load(db, ctx) {
    if (!ctx.projectId || !UUID_RE.test(ctx.subjectId) || ctx.subjectId !== ctx.projectId) return null
    const input = await loadInput(db, ctx.projectId)
    // Sans historique, rien à proposer.
    return input && input.scans.total > 0 ? input : null
  },
  instruction: locale => locale === 'fr'
    ? 'À partir de cet historique de quality gate (métadonnées seulement), propose des seuils de départ réalistes pour ce projet : rules (new_code_only, max_secrets, vuln_block_from, sast_block_from, iac_block_from ; « none » = ne bloque pas), rationale (2 à 6 phrases factuelles : effet attendu sur les analyses et les releases, compromis), exceptions (au plus 8 exceptions candidates, seulement pour des règles listées dans rules de l\'historique, avec un motif et une durée courte). Ne propose jamais d\'exception pour un avis MAL-. Une personne simulera puis décidera : tu proposes seulement, tu ne décides rien.'
    : 'From this quality gate history (metadata only), propose realistic starting thresholds for this project: rules (new_code_only, max_secrets, vuln_block_from, sast_block_from, iac_block_from; "none" = does not block), rationale (2 to 6 factual sentences: expected effect on analyses and releases, trade-offs), exceptions (at most 8 candidate exceptions, only for rules listed in the history rules, with a reason and a short duration). Never propose an exception for a MAL- advisory. A person will simulate and then decide: you only propose, you decide nothing.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['rules', 'rationale', 'exceptions'],
    properties: {
      rules: {
        type: 'object',
        additionalProperties: false,
        required: [...SUGGESTED_KEYS],
        properties: {
          new_code_only: { type: 'boolean' },
          max_secrets: { type: 'integer', minimum: 0, maximum: 50 },
          vuln_block_from: oneOf(SEVERITY_OR_NONE),
          sast_block_from: oneOf(SEVERITY_OR_NONE),
          iac_block_from: oneOf(SEVERITY_OR_NONE),
        },
      },
      rationale: text(1500),
      exceptions: {
        type: 'array',
        maxItems: MAX_EXCEPTIONS,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['tool', 'rule_id', 'reason', 'expires_in_days'],
          properties: {
            tool: text(100),
            rule_id: text(255),
            reason: text(500),
            expires_in_days: { type: 'integer', minimum: 7, maximum: 366 },
          },
        },
      },
    },
  },
  output: SuggestGateOutput,
  finalize: (out, input) => {
    const known = new Set(input.rules.map(r => `${r.tool}\u0000${r.rule_id}`))
    return {
      rules: out.rules,
      rationale: sanitizeText(out.rationale, 1500),
      // Seulement des règles de l'historique, jamais un avis malveillant (H4).
      exceptions: out.exceptions
        .filter(e => known.has(`${e.tool}\u0000${e.rule_id}`) && IDENT_RE.test(e.tool) && IDENT_RE.test(e.rule_id) && !/^MAL-/i.test(e.rule_id))
        .map(e => ({ tool: e.tool, rule_id: e.rule_id, reason: sanitizeText(e.reason, 500), expires_in_days: e.expires_in_days })),
    }
  },
}
