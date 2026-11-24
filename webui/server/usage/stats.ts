// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F14 : consommation réelle par module, calculée sans réglage.
// - scanners : mesures du runner dans scan_modules (mémoire max et médiane,
//   CPU, durée moyenne et p95, nombre d'analyses) sur 30 jours ;
// - modules permanents : relevés de module_samples, en courbes sur 7 et 30 jours ;
// - modules inutilisés depuis N jours (30 par défaut), avec la raison. Un module
//   requis par un autre module installé n'est jamais signalé (G1) ; un service
//   ou un runner n'est jugé que par ce qui en dépend, son usage web n'étant pas
//   mesurable. Le retrait reste une action d'une personne (lien vers la
//   désinstallation existante), jamais automatique.

import { z } from 'zod'
import type { CatalogIndex, InstalledModule } from '../utils/catalog'
import { findModule, latestModules } from '../utils/catalog'
import type { Queryable } from '../utils/db'

/** Fenêtre des statistiques des scanners (jours). */
export const USAGE_WINDOW_DAYS = 30
/** Seuil « inutilisé depuis N jours » par défaut (principe 8 : aucun réglage requis). */
export const DEFAULT_UNUSED_DAYS = 30

/** Statuts d'un module d'analyse qui signifient qu'il a réellement tourné. */
const RAN = `status NOT IN ('pending', 'running', 'missing', 'skipped')`

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

export type UnusedReason = 'no-scan' | 'no-dependent'

export interface ModuleUsage {
  id: string
  type: InstalledModule['type']
  version: string
  enabled: boolean
  installed_at: string | null
  /** Modules installés qui requièrent celui-ci (G1). */
  required_by: string[]
  scanner: ScannerStats | null
  service: ServiceStats | null
  /** Dernière analyse où le module a tourné (scanners). */
  last_used_at: string | null
  /** Le module a pu être jugé (scanner, base ; pas un service ni un runner requis par rien). */
  judged: boolean
  unused: boolean
  unused_reason: UnusedReason | null
}

const num = (v: unknown): number | null => (v === null || v === undefined ? null : Math.round(Number(v)))
const iso = (v: unknown): string | null => (v instanceof Date ? v.toISOString() : typeof v === 'string' ? new Date(v).toISOString() : null)

/** Statistiques des scanners sur la fenêtre, par module. */
export async function scannerStats(db: Queryable, days = USAGE_WINDOW_DAYS, moduleId?: string): Promise<Map<string, ScannerStats>> {
  const args: unknown[] = [days]
  if (moduleId) args.push(moduleId)
  const r = await db.query<Record<string, unknown> & { module_id: string }>(
    `SELECT module_id,
            count(*)::int AS runs,
            count(*) FILTER (WHERE status <> 'ok')::int AS failures,
            max(peak_memory_mb) AS memory_max_mb,
            percentile_cont(0.5) WITHIN GROUP (ORDER BY peak_memory_mb) AS memory_median_mb,
            avg(cpu_ms) AS cpu_avg_ms,
            avg(duration_ms) FILTER (WHERE status = 'ok') AS duration_avg_ms,
            percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms) FILTER (WHERE status = 'ok') AS duration_p95_ms,
            max(COALESCE(finished_at, started_at)) AS last_run_at
       FROM scan_modules
      WHERE ${RAN} AND COALESCE(finished_at, started_at) >= now() - make_interval(days => $1)
        ${moduleId ? 'AND module_id = $2' : ''}
      GROUP BY module_id`, args)
  return new Map(r.rows.map(row => [row.module_id, {
    runs: Number(row.runs),
    failures: Number(row.failures),
    memory_max_mb: num(row.memory_max_mb),
    memory_median_mb: num(row.memory_median_mb),
    cpu_avg_ms: num(row.cpu_avg_ms),
    duration_avg_ms: num(row.duration_avg_ms),
    duration_p95_ms: num(row.duration_p95_ms),
    last_run_at: iso(row.last_run_at),
  }]))
}

/** Dernière exécution de chaque module, sans limite de fenêtre. */
export async function lastRuns(db: Queryable): Promise<Map<string, string>> {
  const r = await db.query<{ module_id: string, at: Date }>(
    `SELECT module_id, max(COALESCE(finished_at, started_at)) AS at
       FROM scan_modules WHERE ${RAN} AND COALESCE(finished_at, started_at) IS NOT NULL GROUP BY module_id`)
  return new Map(r.rows.map(row => [row.module_id, iso(row.at)!]))
}

/** Synthèse des relevés des modules permanents sur la fenêtre. */
export async function serviceStats(db: Queryable, days = USAGE_WINDOW_DAYS, moduleId?: string): Promise<Map<string, ServiceStats>> {
  const args: unknown[] = [days]
  if (moduleId) args.push(moduleId)
  const filter = moduleId ? 'AND module_id = $2' : ''
  const [agg, latest] = await Promise.all([
    db.query<Record<string, unknown> & { module_id: string }>(
      `SELECT module_id, count(*)::int AS samples, avg(memory_mb) AS memory_avg_mb, max(memory_mb) AS memory_max_mb,
              avg(cpu_pct) AS cpu_avg_pct, max(disk_mb) AS disk_max_mb
         FROM module_samples WHERE at >= now() - make_interval(days => $1) ${filter}
        GROUP BY module_id`, args),
    db.query<{ module_id: string, at: Date, memory_mb: number | null, cpu_pct: number | null, disk_mb: number | null }>(
      `SELECT DISTINCT ON (module_id) module_id, at, memory_mb, cpu_pct, disk_mb
         FROM module_samples WHERE at >= now() - make_interval(days => $1) ${filter}
        ORDER BY module_id, at DESC`, args),
  ])
  const last = new Map(latest.rows.map(r => [r.module_id, r]))
  return new Map(agg.rows.map((row) => {
    const l = last.get(row.module_id)
    return [row.module_id, {
      samples: Number(row.samples),
      latest: l ? { at: iso(l.at)!, memory_mb: l.memory_mb, cpu_pct: l.cpu_pct === null ? null : Math.round(l.cpu_pct * 10) / 10, disk_mb: l.disk_mb } : null,
      memory_avg_mb: num(row.memory_avg_mb),
      memory_max_mb: num(row.memory_max_mb),
      cpu_avg_pct: row.cpu_avg_pct === null ? null : Math.round(Number(row.cpu_avg_pct) * 10) / 10,
      disk_max_mb: num(row.disk_max_mb),
    }]
  }))
}

export interface SeriesPoint { at: string, memory_avg_mb: number | null, memory_max_mb: number | null, cpu_avg_pct: number | null, disk_mb: number | null }

/** Courbe d'un module permanent : pas d'une heure sur 7 jours, de quatre heures sur 30. */
export async function serviceSeries(db: Queryable, moduleId: string, days: 7 | 30): Promise<SeriesPoint[]> {
  const step = days === 7 ? '1 hour' : '4 hours'
  const r = await db.query<{ t: Date, mem_avg: string | null, mem_max: number | null, cpu: string | null, disk: number | null }>(
    `SELECT date_bin($2::interval, at, timestamptz 'epoch') AS t,
            avg(memory_mb) AS mem_avg, max(memory_mb) AS mem_max, avg(cpu_pct) AS cpu, max(disk_mb) AS disk
       FROM module_samples
      WHERE module_id = $1 AND at >= now() - make_interval(days => $3)
      GROUP BY 1 ORDER BY 1`, [moduleId, step, days])
  return r.rows.map(row => ({
    at: iso(row.t)!,
    memory_avg_mb: num(row.mem_avg),
    memory_max_mb: row.mem_max,
    cpu_avg_pct: row.cpu === null ? null : Math.round(Number(row.cpu) * 10) / 10,
    disk_mb: row.disk,
  }))
}

/** Modules installés qui requièrent chaque module (G1 : requires.modules, requires.feeds, needs.feeds). */
export function requiredBy(installed: InstalledModule[], index: CatalogIndex | null): Map<string, string[]> {
  const latest = latestModules(index)
  const out = new Map<string, string[]>()
  for (const inst of installed) {
    if (inst.status === 'removing') continue
    const def = findModule(index, inst.id, inst.version) ?? latest.get(inst.id)
    if (!def) continue
    const deps = new Set([...(def.requires?.modules ?? []), ...(def.requires?.feeds ?? []), ...(def.needs?.feeds ?? [])])
    for (const dep of deps) {
      if (dep === inst.id) continue
      out.set(dep, [...(out.get(dep) ?? []), inst.id])
    }
  }
  for (const list of out.values()) list.sort((a, b) => a.localeCompare(b))
  return out
}

export interface UsageInputs {
  installed: InstalledModule[]
  index: CatalogIndex | null
  scanners: Map<string, ScannerStats>
  services: Map<string, ServiceStats>
  lastRuns: Map<string, string>
  unusedDays: number
  now?: number
}

/** Assemble la consommation et le jugement « inutilisé » de chaque module installé. */
export function buildUsage(inp: UsageInputs): ModuleUsage[] {
  const now = inp.now ?? Date.now()
  const deps = requiredBy(inp.installed, inp.index)
  const cutoff = now - inp.unusedDays * 86_400_000
  return inp.installed
    .filter(m => m.status !== 'removing')
    .map((m) => {
      const required = deps.get(m.id) ?? []
      const lastUsed = inp.lastRuns.get(m.id) ?? null
      const installedAt = m.installed_at ? Date.parse(m.installed_at) : Number.NaN
      // Un module installé depuis moins de N jours n'a pas encore eu l'occasion de servir.
      const oldEnough = Number.isNaN(installedAt) || installedAt <= cutoff
      let judged = false
      let reason: UnusedReason | null = null
      if (required.length === 0) {
        if (m.type === 'scanner') {
          judged = true
          if (oldEnough && (!lastUsed || Date.parse(lastUsed) < cutoff)) reason = 'no-scan'
        }
        else if (m.type === 'feed') {
          judged = true
          if (oldEnough) reason = 'no-dependent'
        }
      }
      else {
        judged = true
      }
      return {
        id: m.id,
        type: m.type,
        version: m.version,
        enabled: m.enabled,
        installed_at: m.installed_at ?? null,
        required_by: required,
        scanner: m.type === 'scanner' ? (inp.scanners.get(m.id) ?? emptyScanner()) : null,
        service: m.type === 'scanner' ? null : (inp.services.get(m.id) ?? null),
        last_used_at: lastUsed,
        judged,
        unused: reason !== null,
        unused_reason: reason,
      }
    })
    .sort((a, b) => a.id.localeCompare(b.id))
}

function emptyScanner(): ScannerStats {
  return { runs: 0, failures: 0, memory_max_mb: null, memory_median_mb: null, cpu_avg_ms: null, duration_avg_ms: null, duration_p95_ms: null, last_run_at: null }
}

export interface UsageContext {
  installed: InstalledModule[]
  index: CatalogIndex | null
}

/** Réponse de GET /api/usage/modules. */
export async function listModulesUsage(db: Queryable, ctx: UsageContext, unusedDays = DEFAULT_UNUSED_DAYS) {
  const [scanners, services, runs] = await Promise.all([scannerStats(db), serviceStats(db), lastRuns(db)])
  const modules = buildUsage({ ...ctx, scanners, services, lastRuns: runs, unusedDays })
  return { window_days: USAGE_WINDOW_DAYS, unused_days: unusedDays, unused: modules.filter(m => m.unused).map(m => m.id), modules }
}

/** Réponse de GET /api/usage/modules/:id, avec les courbes d'un module permanent ; null si non installé. */
export async function moduleUsageDetail(db: Queryable, ctx: UsageContext, id: string, unusedDays = DEFAULT_UNUSED_DAYS) {
  const inst = ctx.installed.find(m => m.id === id)
  if (!inst) return null
  const [scanners, services, runs] = await Promise.all([scannerStats(db, USAGE_WINDOW_DAYS, id), serviceStats(db, USAGE_WINDOW_DAYS, id), lastRuns(db)])
  const usage = buildUsage({ ...ctx, scanners, services, lastRuns: runs, unusedDays }).find(m => m.id === id)
  // Module en cours de désinstallation : plus de consommation à montrer.
  if (!usage) return null
  const series = inst.type === 'scanner'
    ? null
    : { 7: await serviceSeries(db, id, 7), 30: await serviceSeries(db, id, 30) }
  return { window_days: USAGE_WINDOW_DAYS, unused_days: unusedDays, usage, series }
}

/** Paramètres de l'API : seuil « inutilisé depuis N jours ». */
export const usageQuery = z.object({
  unused_days: z.coerce.number().int().min(1).max(365).default(DEFAULT_UNUSED_DAYS),
}).strict()
