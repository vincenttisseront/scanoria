// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Côté console des fonctions IA de la 0.5 : résultats semblables (I7) et clé
// d'explication d'une licence (I18). La console lit ce que scanoria-ai a
// calculé ; elle n'appelle jamais Ollama. Rien n'est affiché sans connecteur
// ni pour un projet « aucun envoi à l'IA » : la page reste identique.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { connectorEnabled } from './enqueue'
import { UUID_RE } from './task-kit'
import { licenseKey } from './tasks/license'

export const SimilarQuery = z.strictObject({ finding_id: z.string().regex(UUID_RE) })
export const LicenseKeyQuery = z.strictObject({
  license: z.string().min(1).max(128),
  project_id: z.string().regex(UUID_RE),
})

export const MAX_SIMILAR_SHOWN = 20

export type SimilarState = 'off' | 'opt-out' | 'no-embedding-model' | 'testing' | 'disabled-by-testbed' | 'pending' | 'ready'

export interface SimilarItem {
  id: string
  score: number
  title: string
  tool: string
  rule_id: string
  severity: string
  status: string
  path: string | null
  start_line: number | null
}

/** Modèle d'embedding retenu par la dernière découverte, et son banc d'essai. */
async function embeddingState(db: Queryable): Promise<{ model: string, digest: string, passed: boolean | null, threshold: number | null } | null> {
  const probe = (await db.query<{ model: string | null, digest: string | null }>(
    `SELECT output->'selection'->'embedding'->>'model' AS model, output->'selection'->'embedding'->>'digest' AS digest
       FROM ai_tasks WHERE kind = 'probe' AND status = 'done' ORDER BY finished_at DESC LIMIT 1`,
  )).rows[0]
  if (!probe?.digest || !probe.model) return null
  const tb = (await db.query<{ output: { passed?: unknown, similarity_threshold?: unknown } | null }>(
    `SELECT output FROM ai_tasks WHERE kind = 'testbed' AND subject_id = 'embed-finding' AND status = 'done' AND model_digest = $1
      ORDER BY finished_at DESC LIMIT 1`, [probe.digest],
  )).rows[0]
  return {
    model: probe.model,
    digest: probe.digest,
    passed: typeof tb?.output?.passed === 'boolean' ? tb.output.passed : null,
    threshold: typeof tb?.output?.similarity_threshold === 'number' ? tb.output.similarity_threshold : null,
  }
}

/**
 * Résultats semblables (I7) d'un résultat : relation symétrique tirée des
 * tâches embed-finding faites avec le modèle d'embedding actuel, dans le même
 * projet, résultats encore ouverts. null si le résultat n'existe pas.
 */
export async function similarFindings(db: Queryable, findingId: string) {
  const f = (await db.query<{ project_id: string, ai_opt_out: boolean }>(
    'SELECT f.project_id, p.ai_opt_out FROM findings f JOIN projects p ON p.id = f.project_id WHERE f.id = $1', [findingId],
  )).rows[0]
  if (!f) return null
  const base = { enabled: false, state: 'off' as SimilarState, model: null as string | null, model_digest: null as string | null, threshold: null as number | null, items: [] as SimilarItem[] }
  if (!(await connectorEnabled())) return base
  if (f.ai_opt_out) return { ...base, enabled: true, state: 'opt-out' as const }
  const emb = await embeddingState(db)
  if (!emb) return { ...base, enabled: true, state: 'no-embedding-model' as const }
  const head = { ...base, enabled: true, model: emb.model, model_digest: emb.digest, threshold: emb.threshold }
  if (emb.passed === null) return { ...head, state: 'testing' as const }
  if (!emb.passed) return { ...head, state: 'disabled-by-testbed' as const }
  const { rows } = await db.query<{ subject_id: string, output: { similar?: { id?: unknown, score?: unknown }[] } | null }>(
    `SELECT DISTINCT ON (subject_id) subject_id, output FROM ai_tasks
      WHERE kind = 'embed-finding' AND status = 'done' AND project_id = $1 AND model_digest = $2
        AND (subject_id = $3 OR output->'similar' @> jsonb_build_array(jsonb_build_object('id', $3::text)))
      ORDER BY subject_id, finished_at DESC`,
    [f.project_id, emb.digest, findingId],
  )
  const own = rows.find(r => r.subject_id === findingId)
  if (!own) {
    const pending = (await db.query(
      `SELECT 1 FROM ai_tasks WHERE kind = 'embed-finding' AND subject_id = $1 AND status IN ('queued', 'running') LIMIT 1`, [findingId],
    )).rows.length > 0
    if (pending) return { ...head, state: 'pending' as const }
  }
  const scores = new Map<string, number>()
  const keep = (id: unknown, score: unknown) => {
    if (typeof id !== 'string' || !UUID_RE.test(id) || id === findingId || typeof score !== 'number') return
    scores.set(id, Math.max(scores.get(id) ?? 0, score))
  }
  for (const r of rows) {
    const list = Array.isArray(r.output?.similar) ? r.output.similar : []
    if (r.subject_id === findingId) list.forEach(s => keep(s.id, s.score))
    else keep(r.subject_id, list.find(s => s.id === findingId)?.score)
  }
  if (!scores.size) return { ...head, state: 'ready' as const }
  const found = (await db.query<Omit<SimilarItem, 'score'>>(
    `SELECT id, title, tool, rule_id, severity, status, path, start_line FROM findings
      WHERE id = ANY($1::uuid[]) AND project_id = $2 AND status <> 'fixed'`,
    [[...scores.keys()], f.project_id],
  )).rows
  const items = found
    .map(x => ({ ...x, score: scores.get(x.id)! }))
    .sort((a, b) => b.score - a.score || a.id.localeCompare(b.id))
    .slice(0, MAX_SIMILAR_SHOWN)
  return { ...head, state: 'ready' as const, items }
}

/**
 * Clé d'explication (I18) d'une licence de composant pour un projet : licence
 * du composant et licence déclarée du projet. Aucune clé pour un projet exclu
 * (rien n'est demandé ni affiché). found false si le projet n'existe pas.
 */
export async function licenseKeyFor(db: Queryable, license: string, projectId: string): Promise<{ found: boolean, key: string | null }> {
  const p = (await db.query<{ spdx_license: string | null, ai_opt_out: boolean }>(
    'SELECT spdx_license, ai_opt_out FROM projects WHERE id = $1', [projectId],
  )).rows[0]
  if (!p) return { found: false, key: null }
  if (p.ai_opt_out) return { found: true, key: null }
  return { found: true, key: licenseKey(license, p.spdx_license) }
}
