// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Couverture d'analyse (G15) : ce qui n'a pas été analysé. Les entrées vont
// dans scans.coverage.gaps, à côté de celles de la file d'analyses (C, par
// exemple une catégorie du profil sans module) ; chaque producteur ne remplace
// que ses propres types d'entrée. Le quality gate (E) en fait une raison non
// bloquante en 0.3.

import { join } from 'node:path'
import type { Queryable } from '../utils/db'
import { readModuleHints } from './manifest'
import { readBoundedText } from './fsread'

export type CoverageGap
  = | { kind: 'skipped-files', count: number, reasons: Record<string, number>, sample: string[] }
    | { kind: 'language-without-module', language: string }
    | { kind: 'lockfile-missing', manifest: string, manager: string | null }
    | { kind: 'output-truncated', module: string }
    | { kind: 'output-error', module: string, code: string }

export function scansDir(): string {
  return process.env.SCANORIA_SCANS_DIR || '/var/lib/scanoria/scans'
}

const JOB_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** Fichiers ignorés par le runner (result.json, source.skipped), lecture tolérante. */
export async function skippedFromResult(jobId: string | null): Promise<CoverageGap | null> {
  if (!jobId || !JOB_RE.test(jobId)) return null
  const file = join(scansDir(), 'results', jobId, 'result.json')
  try {
    const text = await readBoundedText(file, 8 * 1024 * 1024)
    if (text === null) return null
    const doc = JSON.parse(text) as { source?: { skipped?: unknown } }
    const skipped = Array.isArray(doc.source?.skipped) ? doc.source.skipped : []
    if (!skipped.length) return null
    const reasons: Record<string, number> = {}
    const sample: string[] = []
    for (const s of skipped.slice(0, 1000)) {
      if (!s || typeof s !== 'object') continue
      const { path, reason } = s as { path?: unknown, reason?: unknown }
      const r = typeof reason === 'string' && /^[a-z-]{1,32}$/.test(reason) ? reason : 'other'
      reasons[r] = (reasons[r] ?? 0) + 1
      if (typeof path === 'string' && sample.length < 20) sample.push(path.slice(0, 1024))
    }
    return { kind: 'skipped-files', count: skipped.length, reasons, sample }
  }
  catch {
    return null
  }
}

interface Detection {
  languages?: unknown
  package_managers?: unknown
  missing_lockfiles?: unknown
}

/** Langages pour lesquels un module d'analyse de code (sast, qualité ; lint pour le shell) suffit. */
function languageCovered(language: string, categories: Set<string>): boolean {
  if (categories.has('sast') || categories.has('quality')) return true
  return (language === 'shell' || language === 'bash') && categories.has('lint')
}

export function gapsFromDetection(detection: Detection | null, moduleCategories: Set<string>): CoverageGap[] {
  if (!detection || typeof detection !== 'object') return []
  const gaps: CoverageGap[] = []
  const languages = Array.isArray(detection.languages) ? detection.languages : []
  for (const l of languages.slice(0, 50)) {
    const name = typeof l === 'string' ? l : l && typeof l === 'object' && typeof (l as { name?: unknown }).name === 'string' ? (l as { name: string }).name : null
    if (!name || !/^[a-z0-9+#.-]{1,32}$/i.test(name)) continue
    if (!languageCovered(name.toLowerCase(), moduleCategories)) gaps.push({ kind: 'language-without-module', language: name.toLowerCase() })
  }
  const seen = new Set<string>()
  const managers = Array.isArray(detection.package_managers) ? detection.package_managers : []
  for (const m of managers.slice(0, 100)) {
    if (!m || typeof m !== 'object') continue
    const { name, manifest, lockfile } = m as { name?: unknown, manifest?: unknown, lockfile?: unknown }
    if (lockfile !== null || typeof manifest !== 'string') continue
    seen.add(manifest)
    gaps.push({ kind: 'lockfile-missing', manifest: manifest.slice(0, 1024), manager: typeof name === 'string' ? name.slice(0, 32) : null })
  }
  const missing = Array.isArray(detection.missing_lockfiles) ? detection.missing_lockfiles : []
  for (const p of missing.slice(0, 100)) {
    if (typeof p === 'string' && !seen.has(p)) {
      seen.add(p)
      gaps.push({ kind: 'lockfile-missing', manifest: p.slice(0, 1024), manager: null })
    }
  }
  return gaps
}

export async function computeCoverage(db: Queryable, scanId: string): Promise<CoverageGap[]> {
  const r = await db.query<{ job_id: string | null, detection: Detection | null }>(
    'SELECT s.job_id::text, p.detection FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = $1',
    [scanId],
  )
  const row = r.rows[0]
  if (!row) return []
  const mods = await db.query<{ module_id: string, module_version: string }>(
    `SELECT module_id, module_version FROM scan_modules WHERE scan_id = $1 AND status = 'ok'`,
    [scanId],
  )
  const categories = new Set<string>()
  for (const m of mods.rows) {
    for (const c of (await readModuleHints(m.module_id, m.module_version)).categories) categories.add(c)
  }
  const gaps: CoverageGap[] = []
  const skipped = await skippedFromResult(row.job_id)
  if (skipped) gaps.push(skipped)
  gaps.push(...gapsFromDetection(row.detection, categories))
  return gaps
}

/**
 * Remplace dans scans.coverage.gaps les entrées des types donnés (pour un
 * module donné si précisé) par les nouvelles ; les autres entrées et les
 * autres clés de coverage restent intactes.
 */
export async function mergeCoverageGaps(db: Queryable, scanId: string, gaps: CoverageGap[], kinds: CoverageGap['kind'][], moduleId?: string): Promise<void> {
  const r = await db.query<{ coverage: Record<string, unknown> | null }>('SELECT coverage FROM scans WHERE id = $1 FOR UPDATE', [scanId])
  const coverage = r.rows[0]?.coverage && typeof r.rows[0].coverage === 'object' ? { ...r.rows[0].coverage } : {}
  const current = Array.isArray(coverage.gaps) ? coverage.gaps as Record<string, unknown>[] : []
  const kept = current.filter(g => !(g && kinds.includes(g.kind as CoverageGap['kind']) && (moduleId === undefined || g.module === moduleId)))
  coverage.gaps = [...kept, ...gaps]
  await db.query('UPDATE scans SET coverage = $2 WHERE id = $1', [scanId, JSON.stringify(coverage)])
}
