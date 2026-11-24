// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 7 de la 0.3 (chantiers-0.3/README.md) : point d'entrée unique des
// tâches IA, appelé par la file d'analyses (C), l'ingestion (D) et la console.
// Sans effet (null) si le connecteur est inactif, si la tâche est inconnue ou
// si le projet est marqué « aucun envoi à l'IA » ; ne lève jamais d'erreur :
// l'IA ne doit jamais faire échouer une analyse (§ 3.5).

import type { AiSubjectType } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { aiPaths, loadEndpoint } from './config'
import { TASKS } from './tasks'

export interface AiTaskRequest {
  kind: string
  subjectType: AiSubjectType
  subjectId: string
  projectId: string | null
  locale?: 'fr' | 'en'
  priority?: number
  requestedBy?: number | null
}

/** Priorités : demande interactive avant précalcul (§ 3.5). */
export const AI_PRIORITY = { interactive: 50, precompute: 10 } as const

let endpointCache: { at: number, enabled: boolean } | undefined

export async function connectorEnabled(maxAgeMs = 10_000): Promise<boolean> {
  if (endpointCache && Date.now() - endpointCache.at < maxAgeMs) return endpointCache.enabled
  const ep = await loadEndpoint(aiPaths().endpointFile)
  endpointCache = { at: Date.now(), enabled: ep.enabled }
  return ep.enabled
}

export function clearConnectorCache(): void {
  endpointCache = undefined
}

/** Dépose une tâche IA ; renvoie son id, ou null si l'IA est inactive ou le projet exclu. */
export async function enqueueAiTask(db: Queryable, req: AiTaskRequest): Promise<string | null> {
  try {
    const def = TASKS[req.kind]
    if (!def || def.subjectType !== req.subjectType || !req.projectId || !/^[0-9a-f-]{36}$/.test(req.subjectId)) return null
    if (!(await connectorEnabled())) return null
    const project = await db.query<{ ai_opt_out: boolean }>(
      'SELECT ai_opt_out FROM projects WHERE id = $1 AND archived_at IS NULL',
      [req.projectId],
    )
    if (project.rows.length !== 1 || project.rows[0]!.ai_opt_out) return null
    let locale = req.locale
    if (!locale) {
      const s = await db.query<{ value: unknown }>(`SELECT value FROM appliance_settings WHERE key = 'ui.default_locale'`)
      locale = s.rows[0]?.value === 'en' ? 'en' : 'fr'
    }
    const priority = Math.max(0, Math.min(100, Math.trunc(req.priority ?? AI_PRIORITY.precompute)))
    // Une demande identique en attente suffit ; un précalcul déjà fait avec le modèle retenu n'est pas refait.
    const existing = await db.query<{ id: string, status: string }>(
      `SELECT id, status FROM ai_tasks
        WHERE kind = $1 AND subject_type = $2 AND subject_id = $3 AND locale = $4
          AND (status IN ('queued', 'running') OR ($5 AND status = 'done' AND model_digest IS NOT DISTINCT FROM (
                SELECT output->'selection'->'tasks'->$1->>'digest' FROM ai_tasks
                 WHERE kind = 'probe' AND status = 'done' ORDER BY finished_at DESC LIMIT 1)))
        ORDER BY created_at DESC LIMIT 1`,
      [req.kind, req.subjectType, req.subjectId, locale, priority < AI_PRIORITY.interactive],
    )
    const found = existing.rows[0]
    if (found) {
      if (found.status === 'queued' && priority >= AI_PRIORITY.interactive) {
        await db.query('UPDATE ai_tasks SET priority = GREATEST(priority, $2) WHERE id = $1', [found.id, priority])
      }
      return found.id
    }
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, locale, priority, requested_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [req.kind, req.projectId, req.subjectType, req.subjectId, locale, priority, req.requestedBy ?? null],
    )
    return rows[0]?.id ?? null
  }
  catch (err) {
    console.error('[ai] enqueue failed:', (err as Error).message)
    return null
  }
}
