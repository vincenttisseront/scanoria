// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Types et formats de la consommation des modules (F14) et de la santé des
// analyses (G20), partagés par l'onglet du Catalogue et la page de santé.

export interface ScannerStats {
  runs: number
  failures: number
  memory_max_mb: number | null
  memory_median_mb: number | null
  cpu_avg_ms: number | null
  duration_avg_ms: number | null
  duration_p95_ms: number | null
  last_run_at: string | null
}

export interface ServiceStats {
  samples: number
  latest: { at: string, memory_mb: number | null, cpu_pct: number | null, disk_mb: number | null } | null
  memory_avg_mb: number | null
  memory_max_mb: number | null
  cpu_avg_pct: number | null
  disk_max_mb: number | null
}

export interface ModuleUsage {
  id: string
  type: 'scanner' | 'service' | 'feed' | 'runner'
  version: string
  enabled: boolean
  installed_at: string | null
  required_by: string[]
  scanner: ScannerStats | null
  service: ServiceStats | null
  last_used_at: string | null
  judged: boolean
  unused: boolean
  unused_reason: 'no-scan' | 'no-dependent' | null
}

export interface SeriesPoint { at: string, memory_avg_mb: number | null, memory_max_mb: number | null, cpu_avg_pct: number | null, disk_mb: number | null }

export interface ModuleUsageDetail {
  window_days: number
  unused_days: number
  usage: ModuleUsage
  series: { 7: SeriesPoint[], 30: SeriesPoint[] } | null
}

export interface ToolHealth {
  module_id: string
  runs: number
  ok: number
  failures: number
  failure_rate: number
  by_class: { infra: number, tool: number, input: number }
  timeouts: number
  oom: number
  invalid_output: number
  duration_avg_ms: number | null
  duration_p95_ms: number | null
  last_failure_at: string | null
}

export interface FailedScan {
  id: string
  number: number
  project_id: string
  project_name: string
  status: string
  finished_at: string | null
  modules: { module_id: string, status: string, error_class: 'infra' | 'tool' | 'input' | null, has_log: boolean }[]
}

export interface ScanHealth {
  windows: { 7: ToolHealth[], 30: ToolHealth[] }
  recent_failures: FailedScan[]
  generated_at: string
}

export function useUsageFormat() {
  const { locale, t } = useI18n()
  const nf = (max = 0) => new Intl.NumberFormat(locale.value === 'en' ? 'en-GB' : 'fr-FR', { maximumFractionDigits: max })
  const none = () => t('usage.notMeasured')
  return {
    mb: (v: number | null | undefined) => (typeof v === 'number' ? (v >= 1024 ? `${nf(1).format(v / 1024)} ${t('usage.gb')}` : `${nf().format(v)} ${t('usage.mbUnit')}`) : none()),
    ms: (v: number | null | undefined) => (typeof v === 'number' ? (v < 1000 ? `${nf().format(v)} ms` : v < 120_000 ? `${nf(1).format(v / 1000)} s` : `${nf(1).format(v / 60_000)} min`) : '—'),
    pct: (v: number | null | undefined) => (typeof v === 'number' ? `${nf(1).format(v)} %` : none()),
    rate: (v: number) => `${nf(1).format(v * 100)} %`,
  }
}
