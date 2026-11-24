// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Analyses (0.3) : types de l'API /api/scans, couleurs d'état et de verdict,
// messages d'erreur propres aux analyses (espace scans.errors).

export interface ScanSummary {
  id: string
  project_id: string
  project_name: string
  project_slug: string
  number: number
  trigger: string
  priority: number
  effective_priority: number
  ref: string
  commit_sha: string | null
  profile: string
  status: string
  verdict: 'passed' | 'failed' | 'inconclusive' | null
  attempt: number
  error: { code?: string, class?: string, message?: string, retry_at?: string } | null
  replay_of: string | null
  /** J6 (0.6) : source d'une analyse de résultats externes. */
  external_source?: { tool: string, version: string | null, format: string, uploaded_via: string } | null
  queued_at: string
  started_at: string | null
  finished_at: string | null
}

export interface ScanModuleRow {
  module_id: string
  module_version: string
  image_digest: string | null
  feeds: { id: string, version: string | null, updated_at?: string | null }[]
  status: string
  error_class: string | null
  attempts: number
  results_count: number | null
  duration_ms: number | null
  has_log: boolean
  started_at: string | null
  finished_at: string | null
}

export interface PlanModule {
  id: string
  version: string
  image_digest: string | null
  categories: string[]
  options: Record<string, unknown>
  feeds: { id: string, version: string | null }[]
  timeout_s: number
  history: 'shallow' | 'full'
  reason: 'category' | 'included'
}

/** Trou de couverture : ceux du plan (profile-*) et ceux de l'ingestion (autres kind). */
export interface CoverageGap {
  kind?: string
  category?: string | null
  module?: string | null
  reason?: string
  path?: string | null
  detail?: string | null
}

export interface ScanDetail extends ScanSummary {
  gate: string
  plan: {
    source: { kind: string, ref: string, commit: string | null, history: string }
    profile: { slug: string, categories: string[] }
    gate: { slug: string }
    modules: PlanModule[]
    gaps: CoverageGap[]
    timeout_s: number
    created_at: string
  } | null
  coverage: { gaps?: CoverageGap[], source?: { files: number, bytes: number, skipped: unknown[] } } & Record<string, unknown> | null
  verdict_details: Record<string, unknown> | null
  requested_by_username: string | null
  by_api_token: boolean
  queue_position: number | null
  modules: ScanModuleRow[]
}

export const ACTIVE_STATUSES = ['queued', 'dispatched', 'running', 'ingesting']

export function scanStatusColor(status: string): 'neutral' | 'info' | 'success' | 'error' | 'warning' {
  if (status === 'done' || status === 'ok') return 'success'
  if (status === 'error' || status === 'timeout' || status === 'oom' || status === 'invalid-output') return 'error'
  if (status === 'cancelled' || status === 'missing' || status === 'skipped') return 'warning'
  if (status === 'pending' || status === 'queued') return 'neutral'
  return 'info'
}

export function verdictColor(verdict: string | null): 'neutral' | 'success' | 'error' | 'warning' {
  if (verdict === 'passed') return 'success'
  if (verdict === 'failed') return 'error'
  if (verdict === 'inconclusive') return 'warning'
  return 'neutral'
}

export function useScanText() {
  const { t, te } = useI18n()
  const { errorMessage } = useApi()
  const label = (space: string, key: string | null | undefined) => (key && te(`scans.${space}.${key}`) ? t(`scans.${space}.${key}`) : (key ?? '—'))
  function scanError(err: unknown): string {
    const code = errorCode(err)
    if (code && te(`scans.errors.${code}`)) return t(`scans.errors.${code}`)
    return errorMessage(err)
  }
  return { label, scanError }
}
