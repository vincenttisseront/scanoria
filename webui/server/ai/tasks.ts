// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tâches IA de la 0.3 (CLAUDE.md § 15) :
// - explain-finding (I2) : ce que la règle détecte, pourquoi c'est un risque
//   ici, impact, correction, références ;
// - explain-verdict (I9) : pourquoi le quality gate bloque, à partir de
//   verdict_details SEULEMENT, et ce qui le débloquerait.
// Chaque tâche lit ses données en restant dans le projet de la tâche
// (cloisonnement), masque les secrets, fixe un schéma JSON passé à Ollama,
// revalide la sortie par zod puis l'échappe. Aucune n'écrit hors des tables ai_*.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { redactText, redactValue } from './redact'
import { allowedLink, referenceLinks, sanitizeDeep, sanitizeText } from './sanitize'
import type { Locale } from './prompt'
import { VerdictDetails } from '#shared/analysis'

/** Version des invites et schémas : entre dans l'empreinte d'entrée (cache). */
export const PROMPT_VERSION = 1

export interface TaskContext {
  projectId: string | null
  subjectId: string
}

export interface TaskDefinition<I = unknown, O = unknown> {
  kind: string
  subjectType: 'finding' | 'scan'
  /** Données d'entrée, déjà masquées ; null = sujet introuvable dans ce projet. */
  load: (db: Queryable, ctx: TaskContext) => Promise<I | null>
  instruction: (locale: Locale) => string
  jsonSchema: Record<string, unknown>
  output: z.ZodType<O>
  /** Échappement et compléments fiables (références) après validation. */
  finalize: (output: O, input: I) => O
  /** Délai d'un appel, en millisecondes. */
  timeoutMs: number
}

// ---- explain-finding (I2) --------------------------------------------------

export interface FindingInput {
  tool: string
  rule_id: string
  category: string
  severity: string
  native_severity: string | null
  title: string
  message: string | null
  path: string | null
  start_line: number | null
  end_line: number | null
  cwe: string[]
  vuln_ids: string[]
  package: { ecosystem?: string, name?: string, version?: string, fixed?: string[] } | null
  malicious: boolean
  secret_type: string | null
  snippet: string | null
}

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

const text = (max: number) => ({ type: 'string', minLength: 1, maxLength: max })

function pickPackage(p: unknown): FindingInput['package'] {
  if (!p || typeof p !== 'object') return null
  const o = p as Record<string, unknown>
  const s = (v: unknown) => (typeof v === 'string' ? v.slice(0, 200) : undefined)
  return {
    ecosystem: s(o.ecosystem),
    name: s(o.name),
    version: s(o.version),
    fixed: Array.isArray(o.fixed) ? o.fixed.filter((x): x is string => typeof x === 'string').slice(0, 10) : undefined,
  }
}

export const explainFinding: TaskDefinition<FindingInput, ExplainFindingOutput> = {
  kind: 'explain-finding',
  subjectType: 'finding',
  timeoutMs: 180_000,
  async load(db, ctx) {
    if (!ctx.projectId) return null
    const { rows } = await db.query(
      `SELECT tool, rule_id, category, severity, native_severity, title, message, path, start_line, end_line,
              cwe, vuln_ids, package, malicious, secret_type, snippet
         FROM findings WHERE id = $1 AND project_id = $2`,
      [ctx.subjectId, ctx.projectId],
    )
    const f = rows[0] as Record<string, unknown> | undefined
    if (!f) return null
    const secret = f.category === 'secrets' || f.secret_type !== null
    const input: FindingInput = {
      tool: String(f.tool).slice(0, 100),
      rule_id: String(f.rule_id).slice(0, 255),
      category: String(f.category).slice(0, 40),
      severity: String(f.severity),
      native_severity: typeof f.native_severity === 'string' ? f.native_severity.slice(0, 64) : null,
      title: redactText(String(f.title)).text,
      // Secret : ni message ni extrait, seulement le type et l'emplacement (F7).
      message: secret || typeof f.message !== 'string' ? null : redactText(f.message).text,
      path: typeof f.path === 'string' ? f.path.slice(0, 1024) : null,
      start_line: typeof f.start_line === 'number' ? f.start_line : null,
      end_line: typeof f.end_line === 'number' ? f.end_line : null,
      cwe: Array.isArray(f.cwe) ? (f.cwe as string[]).slice(0, 10) : [],
      vuln_ids: Array.isArray(f.vuln_ids) ? (f.vuln_ids as string[]).slice(0, 20) : [],
      package: pickPackage(f.package),
      malicious: f.malicious === true,
      secret_type: typeof f.secret_type === 'string' ? f.secret_type.slice(0, 100) : null,
      snippet: secret || typeof f.snippet !== 'string' ? null : redactText(f.snippet).text,
    }
    return input
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

export const TASKS: Record<string, TaskDefinition> = {
  [explainFinding.kind]: explainFinding as unknown as TaskDefinition,
  [explainVerdict.kind]: explainVerdict as unknown as TaskDefinition,
}
export const TASK_KINDS = Object.keys(TASKS)
/** Tâches du service lui-même (sans sujet en base). */
export const SERVICE_KINDS = ['probe', 'testbed'] as const
