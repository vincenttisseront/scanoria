// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ordre et graphe du plan (0.6, chantier D) :
// - V3 : un module qui lit le SBOM de l'analyse (prefers_sbom, requires_sbom)
//   attend ceux qui le produisent (sortie cyclonedx) : modules[].after ;
// - V5 : les modules sont rangés du plus long au plus court, d'après les
//   durées réellement mesurées (scan_modules.duration_ms, F14) sur ce projet,
//   à défaut sur l'appliance, à défaut une valeur par défaut. Le rang d'un
//   module est la durée de sa chaîne la plus longue (lui puis ceux qui
//   l'attendent) : Syft, qui ouvre la chaîne SBOM, part donc tôt.
// Le runner lance les modules prêts dans cet ordre, en parallèle dans la
// limite de la mémoire (G17, schedule.py). L'ordre ne change aucun résultat :
// le rejeu (G11) reprend le plan figé tel quel.

import type { Queryable } from '../utils/db'
import type { PlanCatalogEntry, PlannedModule } from './plan'

/** Durée supposée d'un module jamais mesuré. */
export const DEFAULT_EXPECTED_MS = 60_000
/** Exécutions récentes retenues par module (moyenne). */
export const DURATION_SAMPLE = 10

export interface Durations {
  /** Moyenne des dernières exécutions sur ce projet. */
  project: Map<string, number>
  /** Moyenne des dernières exécutions sur l'appliance. */
  appliance: Map<string, number>
}

/** Rôle d'un module dans la chaîne SBOM (contrat 14), d'après l'index. */
export function sbomRole(m: PlannedModule, catalog: Map<string, PlanCatalogEntry>): 'producer' | 'consumer' | null {
  const scan = catalog.get(`${m.id}@${m.version}`)?.scan
  const consumer = !!scan && scan.inputs.includes('sbom') && (scan.prefers_sbom === true || scan.requires_sbom === true)
  if (consumer) return 'consumer'
  return m.outputs.includes('cyclonedx') ? 'producer' : null
}

export function expectedMs(id: string, durations: Durations): number {
  return Math.max(1, Math.round(durations.project.get(id) ?? durations.appliance.get(id) ?? DEFAULT_EXPECTED_MS))
}

/**
 * Plan rangé (V5) avec son graphe (V3). Fonction pure : mêmes entrées, même
 * ordre (égalités départagées par l'identifiant).
 */
export function orderModules(modules: PlannedModule[], catalog: Map<string, PlanCatalogEntry>, durations: Durations): PlannedModule[] {
  const role = new Map(modules.map(m => [m.id, sbomRole(m, catalog)]))
  const producers = modules.filter(m => role.get(m.id) === 'producer').map(m => m.id).sort()
  const after = new Map(modules.map(m => [m.id, role.get(m.id) === 'consumer' ? producers.filter(p => p !== m.id) : []]))
  const own = new Map(modules.map(m => [m.id, expectedMs(m.id, durations)]))
  // Rang = chaîne la plus longue qui part du module (sans cycle : un consommateur n'est jamais producteur).
  const rank = new Map<string, number>()
  const rankOf = (id: string): number => {
    const known = rank.get(id)
    if (known !== undefined) return known
    const dependents = modules.filter(m => after.get(m.id)!.includes(id)).map(m => rankOf(m.id))
    const r = own.get(id)! + Math.max(0, ...dependents)
    rank.set(id, r)
    return r
  }
  const sorted = [...modules].sort((a, b) => rankOf(b.id) - rankOf(a.id) || own.get(b.id)! - own.get(a.id)! || a.id.localeCompare(b.id))
  // Ordre topologique stable : un module ne précède jamais ce qu'il attend.
  const out: PlannedModule[] = []
  const placed = new Set<string>()
  while (out.length < sorted.length) {
    const next = sorted.find(m => !placed.has(m.id) && after.get(m.id)!.every(d => placed.has(d)))
      ?? sorted.find(m => !placed.has(m.id))!
    placed.add(next.id)
    out.push({ ...next, after: after.get(next.id)!, expected_ms: own.get(next.id)! })
  }
  return out
}

/** Durées mesurées (exécutions réelles et réussies, hors essais F13 et hors sorties réutilisées V4). */
export async function loadDurations(db: Queryable, projectId: string, moduleIds: string[]): Promise<Durations> {
  const durations: Durations = { project: new Map(), appliance: new Map() }
  if (!moduleIds.length) return durations
  const r = await db.query<{ module_id: string, own: boolean, ms: number }>(
    `WITH recent AS (
       SELECT sm.module_id, sm.duration_ms, s.project_id = $1 AS own,
              row_number() OVER (PARTITION BY sm.module_id, s.project_id = $1 ORDER BY sm.finished_at DESC) AS n
         FROM scan_modules sm JOIN scans s ON s.id = sm.scan_id
        WHERE sm.module_id = ANY($2::text[]) AND sm.status = 'ok' AND sm.duration_ms IS NOT NULL
          AND sm.reused_from IS NULL AND s.trigger <> 'trial'
          AND sm.finished_at > now() - interval '60 days')
     SELECT module_id, own, round(avg(duration_ms))::int AS ms FROM recent WHERE n <= $3 GROUP BY module_id, own`,
    [projectId, moduleIds, DURATION_SAMPLE])
  for (const row of r.rows) (row.own ? durations.project : durations.appliance).set(row.module_id, row.ms)
  // Moyenne de l'appliance : ce projet compris.
  for (const [id, ms] of durations.project) if (!durations.appliance.has(id)) durations.appliance.set(id, ms)
  return durations
}
