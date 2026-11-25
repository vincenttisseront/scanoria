// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F2 : comparaison entre deux releases (ou deux analyses d'un même projet).
// Résultats introduits, corrigés et inchangés, par outil et par gravité,
// d'après l'empreinte stable des résultats (G19) : un code déplacé ne compte
// ni comme corrigé ni comme introduit. Lecture seule.
//
// Release précédente trouvée seule : le dernier rapport signé du projet dont
// le tag précède celui-ci dans l'ordre des versions (v1.10.0 après v1.9.2) ;
// elle peut aussi être choisie (page Release).

import type { Queryable } from '../utils/db'
import { SEVERITIES, type Severity } from '#shared/analysis'

export const COMPARE_ITEMS = 200

export type SeverityCounts = Record<Severity, number>

export interface ComparedFinding {
  id: string
  fingerprint: string
  tool: string
  rule_id: string
  severity: Severity
  title: string
  path: string | null
}

export interface CompareBucket {
  total: number
  by_severity: SeverityCounts
  by_tool: Record<string, SeverityCounts>
  /** Les plus graves d'abord, COMPARE_ITEMS au plus. */
  items: ComparedFinding[]
}

export interface Comparison {
  from_scan_id: string
  to_scan_id: string
  introduced: CompareBucket
  fixed: CompareBucket
  unchanged: CompareBucket
}

function emptyCounts(): SeverityCounts {
  return Object.fromEntries(SEVERITIES.map(s => [s, 0])) as SeverityCounts
}

function bucket(list: ComparedFinding[]): CompareBucket {
  const by = emptyCounts()
  const byTool: Record<string, SeverityCounts> = {}
  for (const f of list) {
    by[f.severity]++
    byTool[f.tool] ??= emptyCounts()
    byTool[f.tool]![f.severity]++
  }
  const rank = (s: Severity) => SEVERITIES.indexOf(s)
  const items = [...list].sort((a, b) => rank(a.severity) - rank(b.severity) || a.tool.localeCompare(b.tool)
    || a.rule_id.localeCompare(b.rule_id) || a.fingerprint.localeCompare(b.fingerprint)).slice(0, COMPARE_ITEMS)
  return { total: list.length, by_severity: by, by_tool: byTool, items }
}

/** Résultats d'une analyse, par empreinte (les faux positifs triés n'en font pas partie). */
async function scanFindings(db: Queryable, scanId: string): Promise<Map<string, ComparedFinding>> {
  const r = await db.query<ComparedFinding>(
    `SELECT f.id::text, f.fingerprint, f.tool, f.rule_id, f.severity, f.title, f.path
       FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1 AND f.status <> 'false-positive'`, [scanId])
  return new Map(r.rows.map(f => [`${f.tool}\u0000${f.fingerprint}`, f]))
}

/** F2 : de « from » (release précédente) à « to » (cette release). */
export async function compareScans(db: Queryable, fromScanId: string, toScanId: string): Promise<Comparison> {
  const [a, b] = await Promise.all([scanFindings(db, fromScanId), scanFindings(db, toScanId)])
  const introduced: ComparedFinding[] = []
  const unchanged: ComparedFinding[] = []
  for (const [k, f] of b) (a.has(k) ? unchanged : introduced).push(f)
  const fixed = [...a].filter(([k]) => !b.has(k)).map(([, f]) => f)
  return { from_scan_id: fromScanId, to_scan_id: toScanId, introduced: bucket(introduced), fixed: bucket(fixed), unchanged: bucket(unchanged) }
}

/**
 * Ordre des versions de tags : morceaux numériques comparés comme nombres,
 * le reste comme texte ; une pré-version (« -rc.1 ») précède la version.
 */
export function compareTags(a: string, b: string): number {
  const norm = (t: string) => t.replace(/^[^0-9]*/, '')
  const [ma, pa = null] = norm(a).split(/-(.*)/s)
  const [mb, pb = null] = norm(b).split(/-(.*)/s)
  const parts = (s: string) => s.split(/[.+_]/).map(x => (/^\d+$/.test(x) ? Number(x) : x))
  const cmp = (x: (string | number)[], y: (string | number)[]) => {
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const u = x[i]
      const v = y[i]
      if (u === undefined) return -1
      if (v === undefined) return 1
      if (u === v) continue
      if (typeof u === 'number' && typeof v === 'number') return u - v
      return String(u).localeCompare(String(v))
    }
    return 0
  }
  const main = cmp(parts(ma ?? ''), parts(mb ?? ''))
  if (main) return main
  if (pa === null || pb === null) return pa === null ? (pb === null ? a.localeCompare(b) : 1) : -1
  return cmp(parts(pa), parts(pb)) || a.localeCompare(b)
}

export interface PreviousRelease { scan_id: string, tag: string, commit_sha: string }

/** Release précédente d'une analyse de release (dernier rapport signé du projet), ou null. */
export async function previousRelease(db: Queryable, projectId: string, scanId: string, tag: string): Promise<PreviousRelease | null> {
  const r = await db.query<PreviousRelease & { created_at: Date }>(
    `SELECT rr.scan_id::text, rr.tag, rr.commit_sha, rr.created_at FROM release_reports rr
      WHERE rr.project_id = $1 AND rr.scan_id <> $2 AND rr.status = 'signed' AND rr.tag <> $3
      ORDER BY rr.created_at DESC LIMIT 500`, [projectId, scanId, tag])
  const older = r.rows.filter(x => compareTags(x.tag, tag) < 0).sort((x, y) => compareTags(y.tag, x.tag))
  const pick = older[0] ?? null
  return pick ? { scan_id: pick.scan_id, tag: pick.tag, commit_sha: pick.commit_sha } : null
}
