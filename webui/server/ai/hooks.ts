// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Précalculs IA demandés à l'ingestion des résultats d'un module (contrat 7) :
// - I2 : explication des nouveaux résultats critical / high ;
// - I3 : pré-tri de chaque nouveau résultat (critical / high d'abord) ;
// - I14 : typage des nouveaux secrets génériques ;
// - I17 : traduction des règles rencontrées (une tâche par règle et version
//   d'outil, mise en cache pour toute l'appliance).
// Tout passe par enqueueAiTask : sans connecteur, ou pour un projet « aucun
// envoi à l'IA », rien n'est déposé. Ne lève jamais d'erreur.

import type { Queryable } from '../utils/db'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import { isGenericSecret } from './tasks/secret'
import { ruleKey } from './tasks/translate'

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
}
