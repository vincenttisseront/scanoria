// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tâches IA (CLAUDE.md § 15). Celles de la 0.3, ici :
// - explain-finding (I2) : ce que la règle détecte, pourquoi c'est un risque
//   ici, impact, correction, références ;
// - explain-verdict (I9) : pourquoi le quality gate bloque, à partir de
//   verdict_details SEULEMENT, et ce qui le débloquerait.
// Celles de la 0.4 (I3, I5, I14, I15, I17) et de la 0.5 (I7, I11, I18) sont
// dans server/ai/tasks/, comme celles de la 0.7 (I8 nl-search, I12 generate-rule).
// Briques communes et garde-fous : server/ai/task-kit.ts.

import { z } from 'zod'
import { redactValue } from './redact'
import { allowedLink, referenceLinks, sanitizeDeep, sanitizeText } from './sanitize'
import { VerdictDetails } from '#shared/analysis'
import { findingInput, findingRow, text, type FindingInput, type TaskDefinition } from './task-kit'
import { triageFinding } from './tasks/triage'
import { summarizeScan } from './tasks/summary'
import { classifySecret } from './tasks/secret'
import { diagnoseScan } from './tasks/diagnose'
import { translateRule } from './tasks/translate'
import { embedFinding } from './tasks/similar'
import { assessReachability } from './tasks/reach'
import { explainLicense } from './tasks/license'
import { diagnoseAppliance } from './tasks/diagnose-appliance'
import { nlSearch } from './tasks/nl-search'
import { generateRule } from './tasks/rulegen'
import { draftException } from './tasks/exception'
import { releaseNotes } from './tasks/release-notes'

export type { FindingInput, TaskContext, TaskDefinition } from './task-kit'

/** Version des invites et schémas : entre dans l'empreinte d'entrée (cache). */
export const PROMPT_VERSION = 1

const Reference = z.strictObject({ label: z.string().min(1).max(120), url: z.string().max(300) })
export const ExplainFindingOutput = z.strictObject({
  summary: z.string().min(1).max(600),
  detects: z.string().min(1).max(1200),
  risk: z.string().min(1).max(1500),
  impact: z.string().min(1).max(1200),
  fix: z.string().min(1).max(2000),
  references: z.array(Reference).max(12),
})
export type ExplainFindingOutput = z.infer<typeof ExplainFindingOutput>

export const explainFinding: TaskDefinition<FindingInput, ExplainFindingOutput> = {
  kind: 'explain-finding',
  subjectType: 'finding',
  timeoutMs: 180_000,
  async load(db, ctx) {
    const f = await findingRow(db, ctx)
    return f ? findingInput(f) : null
  },
  instruction: locale => locale === 'fr'
    ? 'Explique ce résultat d\'analyse à un développeur : summary (une phrase), detects (ce que la règle détecte), risk (pourquoi c\'est un risque ici, d\'après l\'extrait et le contexte), impact (conséquence probable), fix (correction recommandée, concrète), references (liens CWE, CVE ou OSV seulement).'
    : 'Explain this analysis finding to a developer: summary (one sentence), detects (what the rule detects), risk (why it is a risk here, based on the snippet and context), impact (likely consequence), fix (concrete recommended fix), references (CWE, CVE or OSV links only).',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'detects', 'risk', 'impact', 'fix', 'references'],
    properties: {
      summary: text(600),
      detects: text(1200),
      risk: text(1500),
      impact: text(1200),
      fix: text(2000),
      references: {
        type: 'array',
        maxItems: 12,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['label', 'url'],
          properties: { label: text(120), url: { type: 'string', maxLength: 300 } },
        },
      },
    },
  },
  output: ExplainFindingOutput,
  finalize(out, input) {
    const clean = sanitizeDeep({ ...out, references: [] as ExplainFindingOutput['references'] }, 2000)
    const trusted = referenceLinks(input.cwe, input.vuln_ids)
    const seen = new Set(trusted.map(r => r.url))
    const fromModel = out.references
      .filter(r => allowedLink(r.url) && /^https:/.test(r.url) && !seen.has(r.url))
      .map(r => ({ label: sanitizeText(r.label, 120), url: r.url }))
    return { ...clean, references: [...trusted, ...fromModel].slice(0, 12) }
  },
}

// ---- explain-verdict (I9) --------------------------------------------------

export interface VerdictInput {
  scan_number: number
  verdict: string
  new_code_only: boolean
  counts: Record<string, number>
  reasons: { code: string, blocking: boolean, count: number, severity: string | null, module: string | null, actions: string[] }[]
  exceptions_applied: { reason: string, expires_on: string }[]
}

export const ExplainVerdictOutput = z.strictObject({
  summary: z.string().min(1).max(1500),
  blocking: z.string().min(1).max(300),
  actions: z.array(z.string().min(1).max(300)).max(8),
})
export type ExplainVerdictOutput = z.infer<typeof ExplainVerdictOutput>

export const explainVerdict: TaskDefinition<VerdictInput, ExplainVerdictOutput> = {
  kind: 'explain-verdict',
  subjectType: 'scan',
  timeoutMs: 120_000,
  async load(db, ctx) {
    if (!ctx.projectId) return null
    const { rows } = await db.query(
      'SELECT number, verdict_details FROM scans WHERE id = $1 AND project_id = $2 AND verdict_details IS NOT NULL',
      [ctx.subjectId, ctx.projectId],
    )
    const row = rows[0] as { number: number, verdict_details: unknown } | undefined
    if (!row) return null
    const parsed = VerdictDetails.safeParse(row.verdict_details)
    if (!parsed.success) return null
    const d = parsed.data
    // verdict_details seulement, sans identifiant de résultat (I9) ; motifs d'exception masqués.
    return redactValue<VerdictInput>({
      scan_number: row.number,
      verdict: d.verdict,
      new_code_only: d.new_code_only,
      counts: d.counts,
      reasons: d.reasons.map(r => ({
        code: r.code, blocking: r.blocking, count: r.count, severity: r.severity, module: r.module, actions: r.actions,
      })),
      exceptions_applied: d.exceptions_applied.map(e => ({ reason: e.reason.slice(0, 500), expires_on: e.expires_on })),
    }).value
  },
  instruction: locale => locale === 'fr'
    ? 'Explique ce verdict de quality gate en clair : summary (pourquoi il est réussi, bloqué ou non concluant), blocking (la cause principale en une phrase), actions (liste ordonnée de ce qui le débloquerait, en reprenant les actions fournies : corriger, demander une exception, rafraîchir une base, installer un module, relancer). N\'invente aucun chiffre.'
    : 'Explain this quality gate verdict in plain words: summary (why it passed, is blocked or is inconclusive), blocking (the main cause in one sentence), actions (ordered list of what would unblock it, using the provided actions: fix, request an exception, refresh a feed, install a module, rerun). Do not invent any number.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['summary', 'blocking', 'actions'],
    properties: {
      summary: text(1500),
      blocking: text(300),
      actions: { type: 'array', maxItems: 8, items: text(300) },
    },
  },
  output: ExplainVerdictOutput,
  finalize: out => sanitizeDeep(out, 1500),
}

export const TASKS: Record<string, TaskDefinition> = Object.fromEntries(
  [explainFinding, explainVerdict, triageFinding, summarizeScan, classifySecret, diagnoseScan, translateRule,
    embedFinding, assessReachability, explainLicense, diagnoseAppliance, draftException, nlSearch, generateRule,
    releaseNotes]
    .map(d => [d.kind, d as unknown as TaskDefinition]),
)
export const TASK_KINDS = Object.keys(TASKS)
/** Tâches de rédaction (modèle de chat) ; les tâches d'embedding (I7) prennent le modèle d'embedding. */
export const COMPLETION_KINDS = TASK_KINDS.filter(k => !TASKS[k]!.embed)
export const EMBED_KINDS = TASK_KINDS.filter(k => !!TASKS[k]!.embed)
/** Tâches du service lui-même (sans sujet en base). */
export const SERVICE_KINDS = ['probe', 'testbed'] as const
