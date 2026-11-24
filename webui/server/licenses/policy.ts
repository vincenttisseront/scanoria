// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F8 : politique de licences. Trois niveaux, du plus fort au plus faible :
//   1. surcharge du projet (license_policies.project_id = projet) ;
//   2. politique globale de l'administrateur (project_id NULL) ;
//   3. défaut versionné ici (principe 8) : licences permissives « autorisées »,
//      tout le reste (copyleft faible ou fort, inconnue, absente) « à revoir ».
// Rien n'est « interdit » par défaut. Une licence inconnue reste « à revoir »
// quel que soit le réglage : seules des licences nommées se règlent.
// Décision d'un composant : chacune de ses entrées de licence (identifiant ou
// expression) est évaluée, et la pire l'emporte (plusieurs entrées CycloneDX
// s'appliquent toutes) ; aucune licence ou une expression illisible = à revoir.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { evaluateSpdx, parseSpdx, SpdxParseError, type LicenseDecision } from './spdx'

export const LICENSE_DECISIONS = ['allowed', 'review', 'denied'] as const
export const DEFAULT_POLICY_VERSION = 1

/** Licences permissives autorisées par défaut (identifiants SPDX). */
export const DEFAULT_ALLOWED: readonly string[] = [
  '0BSD', 'AFL-2.1', 'AFL-3.0', 'Apache-1.1', 'Apache-2.0', 'Artistic-2.0', 'BlueOak-1.0.0',
  'BSD-1-Clause', 'BSD-2-Clause', 'BSD-2-Clause-Patent', 'BSD-3-Clause', 'BSD-3-Clause-Clear',
  'BSD-4-Clause', 'BSL-1.0', 'CC-BY-3.0', 'CC-BY-4.0', 'CC0-1.0', 'ISC', 'MIT', 'MIT-0', 'MIT-CMU',
  'NCSA', 'PostgreSQL', 'PSF-2.0', 'Python-2.0', 'Unicode-3.0', 'Unicode-DFS-2015', 'Unicode-DFS-2016',
  'Unlicense', 'UPL-1.0', 'W3C', 'X11', 'Zlib', 'zlib-acknowledgement',
]

/** Pourquoi une licence a reçu sa décision (affiché : principe 8). */
export type DecisionSource = 'project' | 'global' | 'default' | 'unknown'

export interface PolicyRow {
  id: string
  project_id: string | null
  license: string
  decision: LicenseDecision
  reason: string | null
  updated_by: string | null
  updated_by_username?: string | null
  updated_at: string
}

/** Politique effective d'un projet, prête à évaluer (clés en minuscules). */
export interface EffectivePolicy {
  project: Map<string, LicenseDecision>
  global: Map<string, LicenseDecision>
}

const DEFAULT_SET = new Set(DEFAULT_ALLOWED.map(l => l.toLowerCase()))

/** Licence SPDX simple (identifiant, LicenseRef-…), telle qu'enregistrée dans une politique. */
export const licenseIdSchema = z.string().min(1).max(128).regex(/^(?:DocumentRef-[A-Za-z0-9.-]+:)?[A-Za-z0-9][A-Za-z0-9.-]*$/)

/** Formes équivalentes : « GPL-2.0 » ≡ « GPL-2.0-only », « GPL-2.0+ » ≡ « GPL-2.0-or-later ». */
function candidates(id: string, orLater: boolean): string[] {
  const lower = id.toLowerCase()
  const base = lower.replace(/-(only|or-later)$/, '')
  if (orLater || lower.endsWith('-or-later')) return [`${base}-or-later`, lower, base]
  if (lower.endsWith('-only')) return [lower, base]
  return [lower, `${base}-only`]
}

export function decideLicense(policy: EffectivePolicy, id: string, orLater = false): { decision: LicenseDecision, source: DecisionSource } {
  const keys = candidates(id, orLater)
  for (const [map, source] of [[policy.project, 'project'], [policy.global, 'global']] as const) {
    for (const k of keys) {
      const d = map.get(k)
      if (d) return { decision: d, source }
    }
  }
  if (keys.some(k => DEFAULT_SET.has(k))) return { decision: 'allowed', source: 'default' }
  return { decision: 'review', source: 'default' }
}

/** Décision d'une entrée de licence (identifiant ou expression SPDX). */
export function decideExpression(policy: EffectivePolicy, expr: string): { decision: LicenseDecision, source: DecisionSource } {
  let node
  try {
    node = parseSpdx(expr.trim())
  }
  catch (err) {
    if (err instanceof SpdxParseError) return { decision: 'review', source: 'unknown' }
    throw err
  }
  const sources = new Set<DecisionSource>()
  const decision = evaluateSpdx(node, (id, orLater) => {
    const r = decideLicense(policy, id, orLater)
    sources.add(r.source)
    return r.decision
  })
  const source: DecisionSource = sources.has('project') ? 'project' : sources.has('global') ? 'global' : 'default'
  return { decision, source }
}

/** Décision d'un composant à partir de ses licences (la pire de ses entrées). */
export function decideComponent(policy: EffectivePolicy, licenses: readonly string[]): { decision: LicenseDecision, source: DecisionSource } {
  const list = licenses.filter(l => typeof l === 'string' && l.trim() !== '')
  if (list.length === 0) return { decision: 'review', source: 'unknown' }
  const rank: Record<LicenseDecision, number> = { denied: 0, review: 1, allowed: 2 }
  let out: { decision: LicenseDecision, source: DecisionSource } | null = null
  for (const l of list.slice(0, 32)) {
    const r = decideExpression(policy, l)
    if (!out || rank[r.decision] < rank[out.decision]) out = r
  }
  return out!
}

const toMap = (rows: { license: string, decision: LicenseDecision }[]) => new Map(rows.map(r => [r.license.toLowerCase(), r.decision]))

/** Politique effective d'un projet (ou globale seule si projectId est null). */
export async function loadPolicy(db: Queryable, projectId: string | null): Promise<EffectivePolicy> {
  const r = await db.query<{ project_id: string | null, license: string, decision: LicenseDecision }>(
    `SELECT project_id::text, license, decision FROM license_policies
      WHERE project_id IS NULL OR project_id = $1::uuid`, [projectId])
  return {
    project: toMap(r.rows.filter(x => x.project_id !== null)),
    global: toMap(r.rows.filter(x => x.project_id === null)),
  }
}

const ROW_SQL = `SELECT p.id::text, p.project_id::text, p.license, p.decision, p.reason, p.updated_by::text,
         u.username AS updated_by_username,
         to_char(p.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS updated_at
    FROM license_policies p LEFT JOIN users u ON u.id = p.updated_by`

export async function listPolicyRows(db: Queryable, projectId: string | null | 'all'): Promise<PolicyRow[]> {
  if (projectId === 'all') {
    return (await db.query<PolicyRow>(`${ROW_SQL} ORDER BY p.project_id NULLS FIRST, lower(p.license) LIMIT 5000`)).rows
  }
  return (await db.query<PolicyRow>(
    `${ROW_SQL} WHERE p.project_id IS NOT DISTINCT FROM $1::uuid ORDER BY lower(p.license) LIMIT 5000`, [projectId])).rows
}

export const policyUpsertSchema = z.strictObject({
  project_id: z.string().uuid().nullable().default(null),
  license: licenseIdSchema,
  decision: z.enum(LICENSE_DECISIONS),
  reason: z.string().trim().max(2000).optional(),
})
export type PolicyUpsert = z.infer<typeof policyUpsertSchema>

export class PolicyError extends Error {
  constructor(readonly code: 'E_NOT_FOUND') {
    super(code)
  }
}

/** Crée ou remplace la décision d'une licence (une ligne par projet et par licence, casse ignorée). */
export async function upsertPolicy(db: Queryable, input: PolicyUpsert, userId: number): Promise<{ row: PolicyRow, previous: LicenseDecision | null }> {
  if (input.project_id) {
    const p = await db.query('SELECT 1 FROM projects WHERE id = $1', [input.project_id])
    if (!p.rowCount) throw new PolicyError('E_NOT_FOUND')
  }
  const prev = await db.query<{ id: string, decision: LicenseDecision }>(
    `SELECT id::text, decision FROM license_policies
      WHERE project_id IS NOT DISTINCT FROM $1::uuid AND lower(license) = lower($2) FOR UPDATE`,
    [input.project_id, input.license])
  let id: string
  if (prev.rows[0]) {
    id = prev.rows[0].id
    await db.query(
      `UPDATE license_policies SET license = $2, decision = $3, reason = $4, updated_by = $5, updated_at = now() WHERE id = $1`,
      [id, input.license, input.decision, input.reason || null, userId])
  }
  else {
    const ins = await db.query<{ id: string }>(
      `INSERT INTO license_policies (project_id, license, decision, reason, updated_by)
       VALUES ($1, $2, $3, $4, $5) RETURNING id::text`,
      [input.project_id, input.license, input.decision, input.reason || null, userId])
    id = ins.rows[0]!.id
  }
  const row = (await db.query<PolicyRow>(`${ROW_SQL} WHERE p.id = $1`, [id])).rows[0]!
  return { row, previous: prev.rows[0]?.decision ?? null }
}

export async function deletePolicy(db: Queryable, id: string): Promise<PolicyRow> {
  const row = (await db.query<PolicyRow>(`${ROW_SQL} WHERE p.id = $1`, [id])).rows[0]
  if (!row) throw new PolicyError('E_NOT_FOUND')
  await db.query('DELETE FROM license_policies WHERE id = $1', [id])
  return row
}

/** Décisions de licence des composants d'une analyse (onglet SBOM, gate). */
export async function scanLicenseDecisions(db: Queryable, scanId: string): Promise<{ purl: string, name: string, version: string | null, licenses: string[], decision: LicenseDecision, source: DecisionSource }[]> {
  const c = await db.query<{ project_id: string, purl: string, name: string, version: string | null, licenses: string[] }>(
    `SELECT project_id::text, purl, name, version, licenses FROM sbom_components WHERE scan_id = $1 ORDER BY purl LIMIT 50000`, [scanId])
  if (!c.rows.length) return []
  const policy = await loadPolicy(db, c.rows[0]!.project_id)
  return c.rows.map(r => ({ purl: r.purl, name: r.name, version: r.version, licenses: r.licenses, ...decideComponent(policy, r.licenses) }))
}
