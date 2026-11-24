// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Normalisation des gravités éditable (G5, ARCHITECTURE § 12.6). La gravité
// native d'un résultat devient une clé (« critical », « security-severity:high »,
// « level:warning ») ; severity_maps donne la gravité normalisée pour chaque
// (module, clé). Une ligne est créée au premier usage depuis le manifeste
// (scan.severity_map, contrat 9), sinon depuis les règles par défaut ; un
// administrateur peut la modifier, puis revenir au défaut.

import { SEVERITIES, type Severity } from '#shared/analysis'
import type { Queryable } from '../utils/db'

const LABELS: Record<string, Severity> = {
  critical: 'critical',
  blocker: 'critical',
  high: 'high',
  important: 'high',
  error: 'high',
  major: 'high',
  medium: 'medium',
  moderate: 'medium',
  warning: 'medium',
  low: 'low',
  minor: 'low',
  note: 'low',
  recommendation: 'low',
  negligible: 'low',
  info: 'info',
  informational: 'info',
  information: 'info',
  none: 'info',
  unknown: 'info',
}

/** Gravité issue d'un score CVSS / security-severity (§ 12.6). */
export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

export interface NativeInput {
  /** Étiquette explicite de l'outil (properties.severity, étiquette CRITICAL…). */
  label?: string | null
  /** security-severity SARIF (texte ou nombre). */
  score?: unknown
  /** Niveau SARIF (level du résultat, sinon de la règle). */
  level?: string | null
}

/** Clé native, stable et courte (≤ 64), qui sert d'entrée à severity_maps. */
export function nativeKey(n: NativeInput): string {
  const label = typeof n.label === 'string' ? n.label.trim().toLowerCase() : ''
  if (label && LABELS[label]) return label
  const score = typeof n.score === 'number' ? n.score : typeof n.score === 'string' ? Number.parseFloat(n.score) : Number.NaN
  if (Number.isFinite(score) && score >= 0 && score <= 10) return `security-severity:${severityFromScore(score)}`
  const level = typeof n.level === 'string' && ['error', 'warning', 'note', 'none'].includes(n.level) ? n.level : 'warning'
  return `level:${level}`
}

/** Gravité par défaut d'une clé native (règles du § 12.6). */
export function defaultSeverity(native: string): Severity {
  const bare = native.includes(':') ? native.slice(native.indexOf(':') + 1) : native
  if (native.startsWith('security-severity:') && (SEVERITIES as readonly string[]).includes(bare)) return bare as Severity
  return LABELS[bare.toLowerCase()] ?? 'medium'
}

/**
 * Gravité d'origine : table du manifeste (clé complète ou nue, sans casse),
 * sinon règle par défaut.
 */
export function originSeverity(native: string, manifestMap: Record<string, string> | null | undefined): Severity {
  if (manifestMap) {
    const bare = native.includes(':') ? native.slice(native.indexOf(':') + 1) : native
    for (const [k, v] of Object.entries(manifestMap)) {
      const key = k.trim().toLowerCase()
      if ((key === native || key === bare) && (SEVERITIES as readonly string[]).includes(v)) return v as Severity
    }
  }
  return defaultSeverity(native)
}

/**
 * Gravités normalisées pour un module : crée au premier usage les lignes
 * manquantes (builtin), puis lit la table (les modifications de
 * l'administrateur l'emportent).
 */
export async function resolveSeverities(
  db: Queryable,
  moduleId: string,
  natives: Iterable<string>,
  manifestMap: Record<string, string> | null | undefined,
): Promise<Map<string, Severity>> {
  const keys = [...new Set(natives)].filter(k => k.length > 0 && k.length <= 64)
  const out = new Map<string, Severity>()
  if (!keys.length) return out
  await db.query(
    `INSERT INTO severity_maps (module_id, native, severity, builtin)
     SELECT $1, k, s, true FROM unnest($2::text[], $3::text[]) AS t(k, s)
     ON CONFLICT (module_id, native) DO NOTHING`,
    [moduleId, keys, keys.map(k => originSeverity(k, manifestMap))],
  )
  const rows = await db.query<{ native: string, severity: Severity }>(
    'SELECT native, severity FROM severity_maps WHERE module_id = $1 AND native = ANY($2::text[])',
    [moduleId, keys],
  )
  for (const r of rows.rows) out.set(r.native, r.severity)
  return out
}

export interface SeverityMapRow {
  module_id: string
  native: string
  severity: Severity
  /** Valeur d'origine : manifeste du module, sinon règle par défaut. */
  origin: Severity
  builtin: boolean
  updated_by: string | null
  updated_at: string
}

/** Table complète pour la page d'administration, avec la valeur d'origine. */
export async function listSeverityMaps(
  db: Queryable,
  manifestMapOf: (moduleId: string) => Promise<Record<string, string> | null>,
): Promise<SeverityMapRow[]> {
  const r = await db.query<Omit<SeverityMapRow, 'origin'>>(
    `SELECT m.module_id, m.native, m.severity, m.builtin, u.username AS updated_by,
            to_char(m.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
       FROM severity_maps m LEFT JOIN users u ON u.id = m.updated_by
      ORDER BY m.module_id, m.native`,
  )
  const maps = new Map<string, Record<string, string> | null>()
  const out: SeverityMapRow[] = []
  for (const row of r.rows) {
    if (!maps.has(row.module_id)) maps.set(row.module_id, await manifestMapOf(row.module_id))
    out.push({ ...row, origin: originSeverity(row.native, maps.get(row.module_id)) })
  }
  return out
}

/**
 * Modifie une correspondance (builtin = false), ou revient à la valeur
 * d'origine (severity = null). Renvoie l'ancienne et la nouvelle valeur, ou
 * null si la ligne n'existe pas. Les résultats existants prennent la nouvelle
 * gravité à leur prochaine analyse.
 */
export async function updateSeverityMap(
  db: Queryable,
  moduleId: string,
  native: string,
  severity: Severity | null,
  userId: number | null,
  manifestMap: Record<string, string> | null,
): Promise<{ before: Severity, after: Severity } | null> {
  const cur = await db.query<{ severity: Severity }>('SELECT severity FROM severity_maps WHERE module_id = $1 AND native = $2 FOR UPDATE', [moduleId, native])
  if (!cur.rows[0]) return null
  const after = severity ?? originSeverity(native, manifestMap)
  await db.query(
    'UPDATE severity_maps SET severity = $3, builtin = $4, updated_by = $5, updated_at = now() WHERE module_id = $1 AND native = $2',
    [moduleId, native, after, severity === null, userId],
  )
  return { before: cur.rows[0].severity, after }
}
