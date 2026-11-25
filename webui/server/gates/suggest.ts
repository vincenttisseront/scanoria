// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I19 : une proposition de seuils (tâche IA suggest-gate, server/ai/tasks/gate.ts)
// passe automatiquement dans le simulateur F9 (origin « ai ») : une seule
// simulation par proposition, réutilisée tant que la proposition et les
// règles du gate n'ont pas changé. Les règles candidates sont toujours
// recalculées côté serveur depuis la sortie IA enregistrée, jamais reprises
// du navigateur. Rien n'est enregistré dans le gate : c'est un clic humain
// (PATCH /api/gates/:id avec ai_task_id, audité « proposé par IA »).

import type { GateRules } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { connectorEnabled } from '../ai/enqueue'
import { mergeSuggestedRules, SuggestGateOutput, SUGGEST_WINDOW_DAYS } from '../ai/tasks/gate'
import { getSimulation, sinceFromDays, startSimulation, type SimulationRow } from './simulate'

export interface Suggestion {
  task_id: string
  project_id: string
  gate_id: string
  gate_slug: string
  /** Règles candidates complètes (règles du gate, seuils proposés). */
  rules: GateRules
  output: SuggestGateOutput
  model: string | null
  model_digest: string | null
  finished_at: Date
}

/** Proposition terminée et valide, ou null (connecteur coupé, projet exclu, absente). */
async function suggestionRow(db: Queryable, where: string, param: string): Promise<Suggestion | null> {
  if (!(await connectorEnabled())) return null
  const r = await db.query<{ id: string, project_id: string, gate_id: string, gate_slug: string, gate_rules: unknown, output: unknown, model: string | null, model_digest: string | null, finished_at: Date }>(
    `SELECT t.id, t.project_id, p.gate_id, g.slug AS gate_slug, g.rules AS gate_rules, t.output, t.model, t.model_digest, t.finished_at
       FROM ai_tasks t JOIN projects p ON p.id = t.project_id JOIN gates g ON g.id = p.gate_id
      WHERE t.kind = 'suggest-gate' AND t.status = 'done' AND NOT p.ai_opt_out AND ${where}
      ORDER BY t.finished_at DESC LIMIT 1`, [param])
  const row = r.rows[0]
  if (!row) return null
  const output = SuggestGateOutput.safeParse(row.output)
  if (!output.success) return null
  return {
    task_id: row.id, project_id: row.project_id, gate_id: row.gate_id, gate_slug: row.gate_slug,
    rules: mergeSuggestedRules(row.gate_rules, output.data.rules), output: output.data,
    model: row.model, model_digest: row.model_digest, finished_at: row.finished_at,
  }
}

export function latestSuggestion(db: Queryable, projectId: string): Promise<Suggestion | null> {
  return suggestionRow(db, 't.project_id = $1::uuid AND t.subject_id = $1::text', projectId)
}

export function suggestionByTask(db: Queryable, taskId: string): Promise<Suggestion | null> {
  return suggestionRow(db, 't.id = $1::uuid', taskId)
}

/** Simulation de la dernière proposition d'un projet : réutilisée si elle existe déjà, sinon lancée. */
export async function simulateSuggestion(db: Queryable, projectId: string, userId: number | null): Promise<{ suggestion: Suggestion, simulation: SimulationRow } | null> {
  const suggestion = await latestSuggestion(db, projectId)
  if (!suggestion) return null
  const existing = await db.query<{ id: string }>(
    `SELECT id FROM gate_simulations
      WHERE origin = 'ai' AND project_id = $1 AND rules = $2::jsonb AND created_at >= $3 AND status <> 'error'
      ORDER BY created_at DESC LIMIT 1`, [projectId, JSON.stringify(suggestion.rules), suggestion.finished_at])
  if (existing.rows[0]) return { suggestion, simulation: (await getSimulation(db, existing.rows[0].id))! }
  const simulation = await startSimulation(db, {
    projectId, rules: suggestion.rules, since: sinceFromDays(SUGGEST_WINDOW_DAYS), origin: 'ai', createdBy: userId,
  })
  return { suggestion, simulation }
}
