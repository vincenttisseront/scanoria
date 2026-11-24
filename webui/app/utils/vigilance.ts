// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Formes renvoyées par l'API de vigilance (0.6, chantier B), côté console.

export interface CanaryView {
  module_id: string
  module_version: string
  ok: boolean
  details: { expect: { rule?: string | null, category?: string | null, min: number, found: number, ok: boolean }[], error?: { code: string } }
  duration_ms: number | null
  run_at: string
}

export interface VulnSummary {
  subject: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
  update_available: string | null
}

export interface VigilanceSummary {
  available: boolean
  self_sbom: {
    at: string
    gaps: string[]
    subjects: { subject: string, version: string | null, components: number, error: string | null, tools: { id: string, version: string, ok: boolean }[] }[]
  } | null
  vulns: VulnSummary[]
  alerts: { subject: string, update_available: string, critical: number, high: number, total: number }[]
  canaries: { latest: CanaryView[], failing: string[] }
  retained: { module: string, version: string, kind: 'pin' | 'trial' }[]
  trials: { id: string, module_id: string, to_version: string, status: string }[]
}

export interface TrialView {
  id: string
  module_id: string
  from_version: string
  to_version: string
  status: 'running' | 'done' | 'adopted' | 'abandoned' | 'error'
  sample_size: number
  summary: {
    new: number
    gone: number
    unchanged: number
    scans: number
    failed: number
    duration_old_ms: number | null
    duration_new_ms: number | null
    error?: string | null
    note?: string | null
    per_scan?: { trial_scan_id: string, new_examples: { rule: string, path: string | null }[], gone_examples: { rule: string, path: string | null }[] }[]
  } | null
  started_at: string
  finished_at: string | null
  progress: { total: number, finished: number }
}

export interface SelfVuln {
  vuln_id: string
  purl: string
  severity: string
  fixed_version: string | null
  first_seen: string
}

export function subjectName(subject: string): string {
  return subject.startsWith('module:') ? subject.slice('module:'.length) : subject
}

export function reasonOf(err: unknown): string | undefined {
  return (err as { data?: { data?: { reason?: string } } })?.data?.data?.reason
}
