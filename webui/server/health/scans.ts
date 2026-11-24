// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G20 : santé des analyses par outil, calculée sans réglage sur 7 et 30 jours :
// exécutions, échecs par classe (infra, tool, input : G12), délais dépassés,
// mémoire épuisée, sorties invalides, durées (moyenne, p95). Plus la liste des
// analyses récentes dont un module a échoué, avec un lien vers chacune.

import type { ErrorClass } from '#shared/analysis'
import type { Queryable } from '../utils/db'

export const HEALTH_WINDOWS = [7, 30] as const
export type HealthWindow = (typeof HEALTH_WINDOWS)[number]

/** Statuts d'échec d'un module (ceux qui déclenchent aussi le diagnostic I15). */
export const FAILED_MODULE_STATUSES = ['error', 'timeout', 'oom', 'invalid-output'] as const

export interface ToolHealth {
  module_id: string
  runs: number
  ok: number
  failures: number
  failure_rate: number
  by_class: Record<ErrorClass, number>
  timeouts: number
  oom: number
  invalid_output: number
  duration_avg_ms: number | null
  duration_p95_ms: number | null
  last_failure_at: string | null
}

const num = (v: unknown): number | null => (v === null || v === undefined ? null : Math.round(Number(v)))

/** Santé par outil sur une fenêtre de jours. */
export async function toolHealth(db: Queryable, days: HealthWindow): Promise<ToolHealth[]> {
  const r = await db.query<Record<string, unknown> & { module_id: string }>(
    `SELECT module_id,
            count(*)::int AS runs,
            count(*) FILTER (WHERE status = 'ok')::int AS ok,
            count(*) FILTER (WHERE status <> 'ok')::int AS failures,
            count(*) FILTER (WHERE status <> 'ok' AND error_class = 'infra')::int AS infra,
            count(*) FILTER (WHERE status <> 'ok' AND COALESCE(error_class, 'tool') = 'tool')::int AS tool,
            count(*) FILTER (WHERE status <> 'ok' AND error_class = 'input')::int AS input,
            count(*) FILTER (WHERE status = 'timeout')::int AS timeouts,
            count(*) FILTER (WHERE status = 'oom')::int AS oom,
            count(*) FILTER (WHERE status = 'invalid-output')::int AS invalid_output,
            avg(duration_ms) FILTER (WHERE status = 'ok') AS duration_avg_ms,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE status = 'ok') AS duration_p95_ms,
            max(COALESCE(finished_at, started_at)) FILTER (WHERE status <> 'ok') AS last_failure_at
       FROM scan_modules
      WHERE status IN ('ok', 'error', 'timeout', 'oom', 'invalid-output')
        AND NOT EXISTS (SELECT 1 FROM scans t WHERE t.id = scan_id AND t.trigger = 'trial')
        AND COALESCE(finished_at, started_at) >= now() - make_interval(days => $1)
      GROUP BY module_id
      ORDER BY module_id`, [days])
  return r.rows.map((row) => {
    const runs = Number(row.runs)
    const failures = Number(row.failures)
    const last = row.last_failure_at as Date | null
    return {
      module_id: row.module_id,
      runs,
      ok: Number(row.ok),
      failures,
      failure_rate: runs ? Math.round((failures / runs) * 1000) / 1000 : 0,
      by_class: { infra: Number(row.infra), tool: Number(row.tool), input: Number(row.input) },
      timeouts: Number(row.timeouts),
      oom: Number(row.oom),
      invalid_output: Number(row.invalid_output),
      duration_avg_ms: num(row.duration_avg_ms),
      duration_p95_ms: num(row.duration_p95_ms),
      last_failure_at: last ? new Date(last).toISOString() : null,
    }
  })
}

export interface FailedScan {
  id: string
  number: number
  project_id: string
  project_name: string
  status: string
  finished_at: string | null
  modules: { module_id: string, status: string, error_class: ErrorClass | null, has_log: boolean }[]
}

/** Analyses récentes (30 jours) dont un module a échoué, les plus récentes d'abord. */
export async function recentFailures(db: Queryable, limit = 50): Promise<FailedScan[]> {
  type Row = Omit<FailedScan, 'finished_at'> & { finished_at: Date | null }
  const r = await db.query<Row>(
    `SELECT s.id, s.number, s.project_id, p.name AS project_name, s.status, s.finished_at,
            jsonb_agg(jsonb_build_object('module_id', m.module_id, 'status', m.status, 'error_class', m.error_class,
                                         'has_log', m.log_path IS NOT NULL) ORDER BY m.module_id) AS modules
       FROM scans s
       JOIN projects p ON p.id = s.project_id AND p.archived_at IS NULL
       JOIN scan_modules m ON m.scan_id = s.id AND m.status IN ('error', 'timeout', 'oom', 'invalid-output')
      WHERE s.status IN ('done', 'error') AND s.trigger <> 'trial' AND s.finished_at >= now() - interval '30 days'
      GROUP BY s.id, p.name
      ORDER BY s.finished_at DESC
      LIMIT $1`, [limit])
  return r.rows.map(row => ({ ...row, finished_at: row.finished_at ? new Date(row.finished_at).toISOString() : null }))
}

/** Réponse de GET /api/health/scans. */
export async function scanHealth(db: Queryable) {
  const [d7, d30, failures] = await Promise.all([toolHealth(db, 7), toolHealth(db, 30), recentFailures(db)])
  return { windows: { 7: d7, 30: d30 }, recent_failures: failures, generated_at: new Date().toISOString() }
}
