// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Précalculs IA demandés à l'ingestion des résultats d'un module (contrat 7) :
// - I2 : explication des nouveaux résultats critical / high ;
// - I3 : pré-tri de chaque nouveau résultat (critical / high d'abord) ;
// - I14 : typage des nouveaux secrets génériques ;
// - I17 : traduction des règles rencontrées (une tâche par règle et version
//   d'outil, mise en cache pour toute l'appliance) ;
// - I7 (0.5) : embedding de chaque nouveau résultat, à basse priorité.
// Et après le verdict d'une analyse (enqueueAfterVerdict, 0.5) :
// - I11 : atteignabilité des vulnérabilités de dépendances critical / high ;
// - I18 : explication des licences « à revoir » ou inhabituelles du SBOM.
// Tout passe par enqueueAiTask : sans connecteur, ou pour un projet « aucun
// envoi à l'IA », rien n'est déposé. Ne lève jamais d'erreur.

import type { Queryable } from '../utils/db'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import { isGenericSecret } from './tasks/secret'
import { ruleKey } from './tasks/translate'
import { COMMON_LICENSES, licenseKey } from './tasks/license'
import { enqueueReachability } from './reach'

export interface IngestedFinding {
  id: string
  inserted: boolean
  severity: string
  tool?: string
  rule_id?: string
  category?: string
  secret_type?: string | null
}

/** Au-delà, les autres nouveaux résultats d'un module sont pré-triés à la demande seulement. */
export const MAX_TRIAGE_PER_MODULE = 200
const MAX_RULES_PER_MODULE = 100
/** I7 : au-delà, les embeddings des autres nouveaux résultats d'un module ne sont pas calculés. */
export const MAX_EMBED_PER_MODULE = 500
/** I18 : licences expliquées par analyse. */
export const MAX_LICENSES_PER_SCAN = 20

export async function enqueueFindingTasks(db: Queryable, projectId: string, rows: IngestedFinding[], toolVersion: string | null): Promise<void> {
  if (!rows.some(r => r.inserted)) return
  try {
    if (!(await connectorEnabled())) return
  }
  catch {
    return
  }
  const fresh = rows.filter(r => r.inserted)
  const urgent = (r: IngestedFinding) => r.severity === 'critical' || r.severity === 'high'
  const run = async (what: string, fn: () => Promise<unknown>) => {
    try {
      await fn()
    }
    catch (err) {
      console.error(`[ai] ${what} not queued:`, (err as Error).message)
    }
  }
  for (const r of fresh.filter(urgent)) {
    await run('explain-finding', () => enqueueAiTask(db, { kind: 'explain-finding', subjectType: 'finding', subjectId: r.id, projectId }))
  }
  const ordered = [...fresh.filter(urgent), ...fresh.filter(r => !urgent(r))].slice(0, MAX_TRIAGE_PER_MODULE)
  for (const r of ordered) {
    await run('triage-finding', () => enqueueAiTask(db, {
      kind: 'triage-finding', subjectType: 'finding', subjectId: r.id, projectId,
      priority: urgent(r) ? AI_PRIORITY.precompute : AI_PRIORITY.precompute - 5,
    }))
  }
  for (const r of fresh.filter(x => isGenericSecret(x))) {
    await run('classify-secret', () => enqueueAiTask(db, { kind: 'classify-secret', subjectType: 'finding', subjectId: r.id, projectId }))
  }
  const rules = new Set<string>()
  for (const r of fresh) {
    if (!r.tool || !r.rule_id || r.category === 'secrets') continue
    const key = ruleKey(r.tool, toolVersion, r.rule_id)
    if (key) rules.add(key)
    if (rules.size >= MAX_RULES_PER_MODULE) break
  }
  for (const key of rules) {
    await run('translate-rule', () => enqueueAiTask(db, {
      kind: 'translate-rule', subjectType: 'rule', subjectId: key, projectId: null, priority: AI_PRIORITY.precompute - 5,
    }))
  }
  await enqueueEmbeddings(db, projectId, rows)
}

/** I7 : embeddings des nouveaux résultats, après tout le reste (priorité la plus basse). */
export async function enqueueEmbeddings(db: Queryable, projectId: string, rows: IngestedFinding[]): Promise<void> {
  for (const r of rows.filter(x => x.inserted).slice(0, MAX_EMBED_PER_MODULE)) {
    try {
      await enqueueAiTask(db, { kind: 'embed-finding', subjectType: 'finding', subjectId: r.id, projectId, priority: AI_PRIORITY.precompute - 8 })
    }
    catch (err) {
      console.error('[ai] embed-finding not queued:', (err as Error).message)
    }
  }
}

/** Décision explicite de la politique F8 pour une licence : projet, sinon globale ; null sans règle. */
export function licenseDecision(policies: { license: string, decision: string, project_id: string | null }[], license: string): string | null {
  return policies.find(p => p.license === license && p.project_id !== null)?.decision
    ?? policies.find(p => p.license === license && p.project_id === null)?.decision
    ?? null
}

/** À expliquer : licence mise « à revoir » par la politique, ou inhabituelle et non autorisée explicitement. */
export function licenseNeedsExplanation(decision: string | null, license: string): boolean {
  return decision === 'review' || (!COMMON_LICENSES.has(license) && decision !== 'allowed')
}

/**
 * I18 : licences du SBOM de l'analyse à expliquer, « à revoir » ou
 * inhabituelles (hors des licences courantes, sauf si la politique les
 * autorise). Rien pour un projet « aucun envoi à l'IA ».
 */
export async function enqueueLicenseTasks(db: Queryable, scanId: string, projectId: string): Promise<number> {
  const p = await db.query<{ spdx_license: string | null, ai_opt_out: boolean }>(
    'SELECT spdx_license, ai_opt_out FROM projects WHERE id = $1 AND archived_at IS NULL', [projectId])
  const project = p.rows[0]
  if (!project || project.ai_opt_out) return 0
  const licenses = (await db.query<{ license: string }>(
    `SELECT DISTINCT unnest(licenses) AS license FROM sbom_components WHERE scan_id = $1 AND project_id = $2 ORDER BY 1 LIMIT 500`,
    [scanId, projectId])).rows.map(r => r.license)
  if (!licenses.length) return 0
  const policies = (await db.query<{ license: string, decision: string, project_id: string | null }>(
    'SELECT license, decision, project_id FROM license_policies WHERE project_id = $1 OR project_id IS NULL', [projectId])).rows
  let n = 0
  for (const license of licenses) {
    if (n >= MAX_LICENSES_PER_SCAN) break
    if (!licenseNeedsExplanation(licenseDecision(policies, license), license)) continue
    const key = licenseKey(license, project.spdx_license)
    if (!key) continue
    if (await enqueueAiTask(db, { kind: 'explain-license', subjectType: 'license', subjectId: key, projectId: null })) n++
  }
  return n
}

/** Après le verdict (file d'analyses) : I11 puis I18. Ne lève jamais d'erreur. */
export async function enqueueAfterVerdict(db: Queryable, input: { scanId: string, projectId: string, scansDir: string }): Promise<void> {
  try {
    if (!(await connectorEnabled())) return
    await enqueueReachability(db, input)
    await enqueueLicenseTasks(db, input.scanId, input.projectId)
  }
  catch (err) {
    console.error('[ai] post-verdict tasks not queued:', (err as Error).message)
  }
}
