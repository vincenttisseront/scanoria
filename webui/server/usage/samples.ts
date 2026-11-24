// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F14 : relevés des modules permanents (contrat 11 de la 0.4). Le service root
// publie chaque minute, dans l'état (/run/scanoria/state.json), une clé
// facultative `modules_usage` : [{id, usage: {memory_mb, cpu_pct, disk_mb, at}}].
// Le worker les recopie dans module_samples (un relevé par module et par
// horodatage, donc une recopie répétée ne crée aucun doublon) et purge chaque
// jour ce qui dépasse la rétention (90 jours). Aucune mesure n'est inventée :
// une valeur absente reste NULL.

import { z } from 'zod'
import { MODULE_ID_RE, TIMESTAMP_RE } from '#shared/schemas'
import { readPublishedState } from '../utils/appliance'
import type { Queryable } from '../utils/db'

/** Rétention des relevés (jours), sans réglage (principe 8). */
export const SAMPLE_RETENTION_DAYS = 90

const nonNegInt = z.number().int().min(0).max(16_777_216).nullable().optional()
const usageEntry = z.object({
  id: z.string().regex(MODULE_ID_RE),
  usage: z.object({
    memory_mb: nonNegInt,
    cpu_pct: z.number().min(0).max(102_400).nullable().optional(),
    disk_mb: nonNegInt,
    at: z.string().regex(TIMESTAMP_RE),
  }),
})
export type ModuleUsageEntry = z.infer<typeof usageEntry>

/**
 * Relevés valides de l'état publié ; une entrée mal formée est écartée seule
 * (le reste de l'état ne dépend pas de cette clé).
 */
export function parseModulesUsage(state: Record<string, unknown> | null): ModuleUsageEntry[] {
  const raw = state?.modules_usage
  if (!Array.isArray(raw)) return []
  const out: ModuleUsageEntry[] = []
  const seen = new Set<string>()
  for (const item of raw.slice(0, 256)) {
    const r = usageEntry.safeParse(item)
    if (!r.success) continue
    const key = `${r.data.id}@${r.data.usage.at}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(r.data)
  }
  return out
}

/** Recopie les relevés de l'état dans module_samples ; renvoie le nombre de lignes ajoutées. */
export async function recordModuleSamples(db: Queryable, stateFile: string, now = Date.now()): Promise<number> {
  const published = await readPublishedState(stateFile, now)
  // Un état trop ancien n'apporte plus de relevé nouveau, mais ses relevés restent vrais.
  const entries = parseModulesUsage(published.state)
  if (!entries.length) return 0
  const r = await db.query(
    `INSERT INTO module_samples (module_id, at, memory_mb, cpu_pct, disk_mb)
     SELECT x.id, x.at, x.memory_mb, x.cpu_pct, x.disk_mb
       FROM jsonb_to_recordset($1::jsonb) AS x(id text, at timestamptz, memory_mb integer, cpu_pct real, disk_mb integer)
      WHERE x.at > now() - make_interval(days => $2) AND x.at <= now() + interval '5 minutes'
     ON CONFLICT (module_id, at) DO NOTHING`,
    [JSON.stringify(entries.map(e => ({
      id: e.id,
      at: e.usage.at,
      memory_mb: e.usage.memory_mb ?? null,
      cpu_pct: e.usage.cpu_pct ?? null,
      disk_mb: e.usage.disk_mb ?? null,
    }))), SAMPLE_RETENTION_DAYS],
  )
  return r.rowCount ?? 0
}

/** Purge des relevés plus anciens que la rétention. */
export async function purgeModuleSamples(db: Queryable, retentionDays = SAMPLE_RETENTION_DAYS): Promise<number> {
  const r = await db.query('DELETE FROM module_samples WHERE at < now() - make_interval(days => $1)', [retentionDays])
  return r.rowCount ?? 0
}

export interface UsageTaskOptions {
  stateFile: string
  /** Période de recopie (60 s). */
  periodMs?: number
  log?: (msg: string) => void
}

/**
 * Tâche périodique du worker : recopie toutes les minutes, purge une fois par
 * jour. Ne lève jamais : une erreur est journalisée et la passe suivante réessaie.
 */
export class UsageTask {
  private lastCopy = Number.NEGATIVE_INFINITY
  private lastPurge = Number.NEGATIVE_INFINITY

  constructor(private readonly db: Queryable, private readonly opts: UsageTaskOptions) {}

  async iterate(now = new Date()): Promise<void> {
    const t = now.getTime()
    if (t - this.lastCopy >= (this.opts.periodMs ?? 60_000)) {
      this.lastCopy = t
      try {
        await recordModuleSamples(this.db, this.opts.stateFile, t)
      }
      catch (e) {
        this.opts.log?.(`module samples not recorded: ${(e as Error).message}`)
      }
    }
    if (t - this.lastPurge >= 24 * 3600_000) {
      this.lastPurge = t
      try {
        await purgeModuleSamples(this.db)
      }
      catch (e) {
        this.opts.log?.(`module samples not purged: ${(e as Error).message}`)
      }
    }
  }
}
