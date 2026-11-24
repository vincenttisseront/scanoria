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
import { sanitizeContext } from './context'
import { UUID_RE } from './task-kit'
import { TASKS } from './tasks'

export interface AiTaskRequest {
  kind: string
  subjectType: AiSubjectType
  subjectId: string
  projectId: string | null
  locale?: 'fr' | 'en'
  priority?: number
  requestedBy?: number | null
  /**
   * Contexte joint (I15 : { logs: [{ module, excerpt }] }, voir
   * server/ai/context.ts, aiLogContext). Revalidé, masqué et borné ici ;
   * ignoré pour une autre tâche ou s'il n'est pas conforme.
   */
  context?: unknown
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
    if (!def || def.subjectType !== req.subjectType) return null
    if (!(def.subjectPattern ?? UUID_RE).test(req.subjectId)) return null
    const scoped = def.projectScoped !== false
    if (scoped ? !req.projectId : req.projectId) return null
    if (!(await connectorEnabled())) return null
    if (scoped) {
      const project = await db.query<{ ai_opt_out: boolean }>(
        'SELECT ai_opt_out FROM projects WHERE id = $1 AND archived_at IS NULL',
        [req.projectId],
      )
      if (project.rows.length !== 1 || project.rows[0]!.ai_opt_out) return null
    }
    let locale = req.locale
    if (!locale) {
      const s = await db.query<{ value: unknown }>(`SELECT value FROM appliance_settings WHERE key = 'ui.default_locale'`)
      locale = s.rows[0]?.value === 'en' ? 'en' : 'fr'
    }
    // Les outils écrivent en anglais : rien à traduire pour un lecteur anglophone (I17).
    if (req.kind === 'translate-rule' && locale === 'en') return null
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
    let context = sanitizeContext(req.kind, req.context)
    if (!context && req.context === undefined && req.kind === 'diagnose-scan') {
      // Nouvelle demande (depuis la console) : le contexte joint par la file d'analyses est repris.
      const prev = await db.query<{ context: unknown }>(
        `SELECT context FROM ai_tasks WHERE kind = $1 AND subject_type = $2 AND subject_id = $3 AND context IS NOT NULL
          ORDER BY created_at DESC LIMIT 1`,
        [req.kind, req.subjectType, req.subjectId],
      )
      context = sanitizeContext(req.kind, prev.rows[0]?.context)
    }
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO ai_tasks (kind, project_id, subject_type, subject_id, locale, priority, requested_by, context)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [req.kind, scoped ? req.projectId : null, req.subjectType, req.subjectId, locale, priority, req.requestedBy ?? null,
        context ? JSON.stringify(context) : null],
    )
    return rows[0]?.id ?? null
  }
  catch (err) {
    console.error('[ai] enqueue failed:', (err as Error).message)
    return null
  }
}
