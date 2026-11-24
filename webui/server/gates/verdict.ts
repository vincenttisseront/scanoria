// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// État et verdict d'une analyse pour la CI et la console (GET /api/scans/:id/verdict),
// avec, s'il existe, le texte d'explication rédigé par l'IA (I9, chantier F),
// marqué comme tel et jamais pris en compte dans le verdict.

import type { Queryable } from '../utils/db'
import { connectorEnabled } from '../ai/enqueue'
import { VerdictDetails, type ScanStatus, type Verdict } from '#shared/analysis'

export interface AiSummary {
  summary: string
  model: string | null
  model_digest: string | null
  generated_at: string | null
}

export interface ScanVerdict {
  scan_id: string
  number: number
  project_id: string
  ref: string
  commit: string | null
  status: ScanStatus
  verdict: Verdict | null
  details: VerdictDetails | null
  error: { code?: string, class?: string } | null
  queued_at: string
  finished_at: string | null
  url: string
  ai_summary?: AiSummary
}

const FINAL: ScanStatus[] = ['done', 'error', 'cancelled']

export function isFinal(status: ScanStatus): boolean {
  return FINAL.includes(status)
}

export async function getScanVerdict(db: Queryable, scanId: string, locale: 'fr' | 'en'): Promise<ScanVerdict | null> {
  const res = await db.query<Omit<ScanVerdict, 'url' | 'ai_summary' | 'details' | 'error'> & { details: unknown, error: unknown }>(
    `SELECT id AS scan_id, number, project_id, ref, commit_sha AS commit, status, verdict,
            verdict_details AS details, error,
            to_char(queued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS queued_at,
            to_char(finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at
       FROM scans WHERE id = $1`,
    [scanId],
  )
  const row = res.rows[0]
  if (!row) return null
  const parsed = VerdictDetails.safeParse(row.details)
  const err = row.error && typeof row.error === 'object' ? row.error as Record<string, unknown> : null
  const out: ScanVerdict = {
    ...row,
    details: parsed.success ? parsed.data : null,
    // Le message d'erreur brut reste dans la console : seuls code et classe sortent.
    error: err ? { code: typeof err.code === 'string' ? err.code : undefined, class: typeof err.class === 'string' ? err.class : undefined } : null,
    url: `/scans/${row.scan_id}`,
  }
  if (row.verdict) {
    const ai = await aiSummary(db, scanId, locale)
    if (ai) out.ai_summary = ai
  }
  return out
}

async function aiSummary(db: Queryable, scanId: string, locale: 'fr' | 'en'): Promise<AiSummary | null> {
  // Sans connecteur, la réponse est celle d'une appliance sans IA (CLAUDE.md § 3.5).
  if (!(await connectorEnabled())) return null
  const res = await db.query<{ output: unknown, model: string | null, model_digest: string | null, finished_at: string | null }>(
    `SELECT output, model, model_digest,
            to_char(finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at
       FROM ai_tasks
      WHERE kind = 'explain-verdict' AND subject_type = 'scan' AND subject_id = $1 AND status = 'done'
        AND NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = ai_tasks.project_id AND p.ai_opt_out)
      ORDER BY (locale = $2) DESC, finished_at DESC NULLS LAST
      LIMIT 1`,
    [scanId, locale],
  )
  const row = res.rows[0]
  const summary = (row?.output as { summary?: unknown } | null)?.summary
  if (!row || typeof summary !== 'string' || !summary.trim()) return null
  return { summary: summary.slice(0, 2000), model: row.model, model_digest: row.model_digest, generated_at: row.finished_at }
}
