// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I15, diagnostic d'une analyse en échec (diagnose-scan), demandé par la file
// d'analyses (chantier C) quand un module finit en error, timeout, oom ou
// invalid-output. Le service scanoria-ai n'a aucun accès aux journaux sur
// disque : l'appelant joint un extrait masqué et borné (ai_tasks.context,
// voir server/ai/context.ts), masqué de nouveau ici.
//
// Le modèle donne la cause probable et la correction. Le réglage de
// ressources proposé (délai d'un module) ne vient PAS du modèle : il est
// calculé ici à partir des faits (statut timeout, délai du plan), borné, et
// recalculé côté console avant d'être appliqué par un clic (safeTimeoutProposal).

import { z } from 'zod'
import type { Queryable } from '../../utils/db'
import { parsePlan } from '../../scans/plan'
import { redactText } from '../redact'
import { sanitizeText } from '../sanitize'
import { oneOf, text, UUID_RE, type TaskDefinition } from '../task-kit'
import { AiLogContext } from '../context'

export const DIAGNOSE_CAUSES = ['memory', 'timeout', 'image', 'invalid-input', 'invalid-output', 'tool-error', 'infrastructure', 'unknown'] as const
const FAILED = ['error', 'timeout', 'oom', 'invalid-output', 'missing'] as const
/** Plafond d'un délai proposé (secondes). */
export const MAX_PROPOSED_TIMEOUT_S = 3 * 3600

export interface FailedModule {
  module: string
  version: string
  status: string
  error_class: string | null
  attempts: number
  duration_ms: number | null
  timeout_s: number | null
  peak_memory_mb: number | null
}

export interface DiagnoseInput {
  scan_number: number
  scan_status: string
  scan_error: { code: string, class: string | null, message: string } | null
  modules: FailedModule[]
  logs: { module: string, excerpt: string }[]
}

export interface TimeoutProposal {
  kind: 'timeout'
  module: string
  current_s: number
  proposed_s: number
}

export const DiagnoseOutput = z.strictObject({
  cause: z.enum(DIAGNOSE_CAUSES),
  module: z.string().max(64).nullable(),
  summary: z.string().min(1).max(600),
  fix: z.string().min(1).max(800),
  steps: z.array(z.string().min(1).max(300)).max(5),
  /** Ajouté après validation, calculé sans le modèle. */
  proposal: z.strictObject({ kind: z.literal('timeout'), module: z.string(), current_s: z.int(), proposed_s: z.int() }).nullable().optional(),
})
export type DiagnoseOutput = z.infer<typeof DiagnoseOutput>

/** Délai doublé (au moins 10 min de plus), plafonné : seul réglage proposé en un clic. */
export function proposeTimeout(m: Pick<FailedModule, 'module' | 'status' | 'timeout_s'>): TimeoutProposal | null {
  if (m.status !== 'timeout' || !m.timeout_s || m.timeout_s >= MAX_PROPOSED_TIMEOUT_S) return null
  const proposed = Math.min(MAX_PROPOSED_TIMEOUT_S, Math.max(m.timeout_s * 2, m.timeout_s + 600))
  return { kind: 'timeout', module: m.module, current_s: m.timeout_s, proposed_s: proposed }
}

/** Modules en échec d'une analyse du projet, avec le délai que le plan leur donnait. */
export async function failedModules(db: Queryable, scanId: string, projectId: string): Promise<{ scan: { number: number, status: string, error: unknown } | null, modules: FailedModule[] }> {
  const s = await db.query<{ number: number, status: string, error: unknown, plan: unknown }>(
    'SELECT number, status, error, plan FROM scans WHERE id = $1 AND project_id = $2',
    [scanId, projectId],
  )
  const scan = s.rows[0]
  if (!scan) return { scan: null, modules: [] }
  const plan = parsePlan(scan.plan)
  const timeouts = new Map((plan?.modules ?? []).map(m => [m.id, m.timeout_s]))
  const { rows } = await db.query<{ module_id: string, module_version: string, status: string, error_class: string | null, attempts: number, duration_ms: number | null, peak_memory_mb: number | null }>(
    `SELECT module_id, module_version, status, error_class, attempts, duration_ms, peak_memory_mb
       FROM scan_modules WHERE scan_id = $1 AND status = ANY($2::text[]) ORDER BY module_id LIMIT 20`,
    [scanId, FAILED],
  )
  return {
    scan: { number: scan.number, status: scan.status, error: scan.error },
    modules: rows.map(r => ({
      module: r.module_id,
      version: r.module_version.slice(0, 64),
      status: r.status,
      error_class: r.error_class,
      attempts: r.attempts,
      duration_ms: r.duration_ms,
      timeout_s: timeouts.get(r.module_id) ?? null,
      peak_memory_mb: r.peak_memory_mb,
    })),
  }
}

function scanError(e: unknown): DiagnoseInput['scan_error'] {
  if (!e || typeof e !== 'object') return null
  const o = e as Record<string, unknown>
  if (typeof o.code !== 'string') return null
  return {
    code: o.code.slice(0, 64),
    class: typeof o.class === 'string' ? o.class.slice(0, 16) : null,
    message: redactText(typeof o.message === 'string' ? o.message.slice(0, 1000) : '').text,
  }
}

export const diagnoseScan: TaskDefinition<DiagnoseInput, DiagnoseOutput> = {
  kind: 'diagnose-scan',
  subjectType: 'scan',
  timeoutMs: 120_000,
  async load(db, ctx) {
    if (!ctx.projectId || !UUID_RE.test(ctx.subjectId)) return null
    const { scan, modules } = await failedModules(db, ctx.subjectId, ctx.projectId)
    if (!scan || (modules.length === 0 && scan.status !== 'error')) return null
    const parsed = AiLogContext.safeParse(ctx.context ?? { logs: [] })
    const logs = (parsed.success ? parsed.data.logs : [])
      .filter(l => modules.length === 0 || modules.some(m => m.module === l.module))
      .map(l => ({ module: l.module, excerpt: redactText(l.excerpt).text }))
    return { scan_number: scan.number, scan_status: scan.status, scan_error: scanError(scan.error), modules, logs }
  },
  instruction: locale => locale === 'fr'
    ? 'Diagnostique cette analyse en échec à partir des modules en échec et des extraits de journal : cause parmi memory, timeout, image, invalid-input, invalid-output, tool-error, infrastructure, unknown ; module (identifiant du module en cause, ou null) ; summary (cause probable en clair) ; fix (correction recommandée) ; steps (au plus 5 étapes concrètes dans la console : relancer, mettre à jour le module, rafraîchir une base, augmenter une ressource…). N\'invente aucune option de ligne de commande.'
    : 'Diagnose this failed analysis from the failed modules and the log excerpts: cause among memory, timeout, image, invalid-input, invalid-output, tool-error, infrastructure, unknown; module (id of the module at fault, or null); summary (probable cause in plain words); fix (recommended fix); steps (at most 5 concrete steps in the console: rerun, update the module, refresh a feed, raise a resource…). Do not invent any command line option.',
  jsonSchema: {
    type: 'object',
    additionalProperties: false,
    required: ['cause', 'module', 'summary', 'fix', 'steps'],
    properties: {
      cause: oneOf(DIAGNOSE_CAUSES),
      module: { type: ['string', 'null'], maxLength: 64 },
      summary: text(600),
      fix: text(800),
      steps: { type: 'array', maxItems: 5, items: text(300) },
    },
  },
  output: DiagnoseOutput,
  finalize(out, input) {
    const known = input.modules.find(m => m.module === out.module)
    // Réglage proposé : depuis les faits seulement (un module réellement arrivé à son délai).
    const proposal = input.modules.map(proposeTimeout).find(p => p !== null) ?? null
    return {
      cause: out.cause,
      module: known ? known.module : null,
      summary: sanitizeText(out.summary, 600),
      fix: sanitizeText(out.fix, 800),
      steps: out.steps.map(s => sanitizeText(s, 300)),
      proposal,
    }
  },
}
