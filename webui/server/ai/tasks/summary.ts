// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I5, résumé d'analyse (summarize-scan) : quelques lignes en tête de la page
// d'analyse : ce qui a changé, les trois priorités, ce qui bloque, ce qui n'a
// pas été couvert (G15). Demandé par la file d'analyses après le verdict,
// comme explain-verdict.
//
// Les priorités sont choisies par le modèle parmi des candidats numérotés ;
// les identifiants et les liens sont reconstruits ici, jamais recopiés de la
// sortie du modèle. Rien n'est lu hors du projet de l'analyse.

import { z } from 'zod'
import { VerdictDetails } from '#shared/analysis'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { text, UUID_RE, type TaskDefinition } from '../task-kit'

const MAX_CANDIDATES = 10
const SEVERITY_ORDER = `CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`

export interface SummaryCandidate {
  ref: number
  tool: string
  rule_id: string
  severity: string
  title: string
  path: string | null
  line: number | null
  malicious: boolean
  secret: boolean
}

export interface SummaryInput {
  scan_number: number
  ref: string
  status: string
  verdict: string | null
  blocking_reasons: { code: string, count: number, module: string | null }[]
  new_by_severity: Record<string, number>
  fixed_count: number
  open_count: number
  candidates: SummaryCandidate[]
  not_covered: { kind: string, detail: string }[]
  failed_modules: { module: string, status: string }[]
  /** Hors invite : identifiants des candidats, pour reconstruire les liens. */
  _ids?: string[]
  _scan_id?: string
}

export const SummaryOutput = z.strictObject({
  headline: z.string().min(1).max(300),
  changes: z.string().min(1).max(800),
  priorities: z.array(z.strictObject({
    ref: z.int().min(1).max(MAX_CANDIDATES),
    why: z.string().min(1).max(300),
    finding_id: z.string().optional(),
    link: z.string().optional(),
    severity: z.string().optional(),
  })).max(3),
  blocking: z.string().min(1).max(400),
  not_covered: z.string().min(1).max(400),
})
export type SummaryOutput = z.infer<typeof SummaryOutput>

function describeGap(g: Record<string, unknown>): { kind: string, detail: string } | null {
  const kind = typeof g.kind === 'string' ? g.kind.slice(0, 40) : null
  if (!kind) return null
  const parts = ['language', 'module', 'category', 'manifest', 'reason', 'code', 'count']
    .filter(k => g[k] !== undefined && g[k] !== null)
    .map(k => `${k}=${String(g[k]).slice(0, 120)}`)
  return { kind, detail: redactText(parts.join(' ')).text }
}

export const summarizeScan: TaskDefinition<SummaryInput, SummaryOutput> = {
  kind: 'summarize-scan',
  subjectType: 'scan',
  timeoutMs: 120_000,
  async load(db, ctx) {
    if (!ctx.projectId || !UUID_RE.test(ctx.subjectId)) return null
    const { rows } = await db.query<{ number: number, ref: string, status: string, verdict: string | null, verdict_details: unknown, coverage: unknown }>(
      `SELECT number, ref, status, verdict, verdict_details, coverage FROM scans
        WHERE id = $1 AND project_id = $2 AND status IN ('done', 'error')`,
      [ctx.subjectId, ctx.projectId],
    )
    const scan = rows[0]
    if (!scan) return null
    const details = VerdictDetails.safeParse(scan.verdict_details)
    const counts = await db.query<{ severity: string, n: number }>(
      `SELECT f.severity, count(*)::int AS n FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
        WHERE sf.scan_id = $1 AND sf.is_new AND f.project_id = $2 GROUP BY f.severity`,
      [ctx.subjectId, ctx.projectId],
    )
    const totals = await db.query<{ open: number, fixed: number }>(
      `SELECT (SELECT count(*)::int FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
                WHERE sf.scan_id = $1 AND f.project_id = $2 AND f.status NOT IN ('fixed', 'false-positive')) AS open,
              (SELECT count(*)::int FROM findings x
                WHERE x.project_id = $2 AND x.status = 'fixed' AND x.status_at >= (SELECT queued_at FROM scans WHERE id = $1)
                  AND NOT EXISTS (SELECT 1 FROM scan_findings y WHERE y.scan_id = $1 AND y.finding_id = x.id)) AS fixed`,
      [ctx.subjectId, ctx.projectId],
    )
    const cand = await db.query<{ id: string, tool: string, rule_id: string, severity: string, title: string, path: string | null, start_line: number | null, malicious: boolean, category: string }>(
      `SELECT f.id, f.tool, f.rule_id, f.severity, f.title, f.path, f.start_line, f.malicious, f.category
         FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
        WHERE sf.scan_id = $1 AND sf.is_new AND f.project_id = $2 AND f.status IN ('new', 'confirmed')
        ORDER BY f.malicious DESC, ${SEVERITY_ORDER}, (f.category = 'secrets') DESC, f.id
        LIMIT ${MAX_CANDIDATES}`,
      [ctx.subjectId, ctx.projectId],
    )
    const modules = await db.query<{ module_id: string, status: string }>(
      `SELECT module_id, status FROM scan_modules WHERE scan_id = $1 AND status NOT IN ('ok', 'skipped', 'pending', 'running') ORDER BY module_id`,
      [ctx.subjectId],
    )
    const gaps = scan.coverage && typeof scan.coverage === 'object' && Array.isArray((scan.coverage as { gaps?: unknown }).gaps)
      ? ((scan.coverage as { gaps: unknown[] }).gaps).filter((g): g is Record<string, unknown> => !!g && typeof g === 'object').map(describeGap).filter(g => g !== null).slice(0, 15)
      : []
    const newBy: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const c of counts.rows) newBy[c.severity] = c.n
    return {
      scan_number: scan.number,
      ref: scan.ref.slice(0, 255),
      status: scan.status,
      verdict: scan.verdict,
      blocking_reasons: details.success
        ? details.data.reasons.filter(r => r.blocking).slice(0, 10).map(r => ({ code: r.code, count: r.count, module: r.module }))
        : [],
      new_by_severity: newBy,
      fixed_count: totals.rows[0]?.fixed ?? 0,
      open_count: totals.rows[0]?.open ?? 0,
      candidates: cand.rows.map((r, i) => ({
        ref: i + 1,
        tool: r.tool.slice(0, 100),
        rule_id: r.rule_id.slice(0, 255),
        severity: r.severity,
        title: redactText(r.title.slice(0, 300)).text,
        path: r.path ? r.path.slice(0, 300) : null,
        line: r.start_line,
        malicious: r.malicious,
        secret: r.category === 'secrets',
      })),
      not_covered: gaps,
      failed_modules: modules.rows.map(m => ({ module: m.module_id, status: m.status })),
      _ids: cand.rows.map(r => r.id),
      _scan_id: ctx.subjectId,
    }
  },
  instruction: locale => locale === 'fr'
    ? 'Résume cette analyse pour l\'équipe, en quelques lignes : headline (une phrase), changes (ce qui a changé : nouveaux résultats par gravité, corrigés), priorities (au plus 3 candidats à traiter en premier, par leur numéro ref, avec why), blocking (ce qui bloque le quality gate, ou « rien »), not_covered (ce qui n\'a pas été analysé, ou « tout a été couvert »). N\'invente aucun chiffre.'
    : 'Summarise this analysis for the team in a few lines: headline (one sentence), changes (what changed: new findings by severity, fixed ones), priorities (at most 3 candidates to handle first, by their ref number, with why), blocking (what blocks the quality gate, or "nothing"), not_covered (what was not analysed, or "everything was covered"). Do not invent any number.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['headline', 'changes', 'priorities', 'blocking', 'not_covered'],
    properties: {
      headline: text(300),
      changes: text(800),
      priorities: {
        type: 'array',
        maxItems: 3,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['ref', 'why'],
          properties: { ref: { type: 'integer', minimum: 1, maximum: MAX_CANDIDATES }, why: text(300) },
        },
      },
      blocking: text(400),
      not_covered: text(400),
    },
  },
  output: SummaryOutput,
  finalize(out, input) {
    const ids = input._ids ?? []
    const seen = new Set<number>()
    const priorities = out.priorities
      .filter(p => p.ref >= 1 && p.ref <= input.candidates.length && !seen.has(p.ref) && seen.add(p.ref))
      .map((p) => {
        const c = input.candidates[p.ref - 1]!
        const id = ids[p.ref - 1]
        return {
          ref: p.ref,
          why: sanitizeText(p.why, 300),
          // Le titre du résultat n'est pas recopié : la page l'affiche depuis la base (donnée, pas sortie IA).
          severity: c.severity,
          ...(id && input._scan_id ? { finding_id: id, link: `/findings?scan=${input._scan_id}&ids=${id}` } : {}),
        }
      })
    return {
      headline: sanitizeText(out.headline, 300),
      changes: sanitizeText(out.changes, 800),
      priorities,
      blocking: sanitizeText(out.blocking, 400),
      not_covered: sanitizeText(out.not_covered, 400),
    }
  },
}
