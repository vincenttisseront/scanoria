// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I24, retours et qualité mesurée : 👍/👎 et correction d'une personne sur
// une sortie IA (table ai_feedback, migration 006), et taux d'accord IA/humain
// par tâche et par modèle, affiché sur la page Système › IA.
//
// Deux mesures, sans réentraînement :
// - accord déclaré : part des 👍 parmi les votes ;
// - accord constaté pour le pré-tri (I3) : la suggestion comparée au tri que
//   des personnes ont fait ensuite (faux positif ↔ « faux positif probable »,
//   confirmé ↔ « vrai positif probable »).
// Les tris confirmés servent d'exemples dans l'invite du même projet
// seulement (server/ai/tasks/triage.ts). Un retour n'est jamais envoyé à
// l'IA d'un autre projet, ni à l'IA du tout : il sert à mesurer.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { redact } from '../findings/redact'

export const FeedbackBody = z.strictObject({
  task_id: z.uuid(),
  vote: z.union([z.literal(1), z.literal(-1)]),
  correction: z.string().trim().min(1).max(4000).nullable().optional(),
})
export type FeedbackBody = z.infer<typeof FeedbackBody>

/** Enregistre (ou remplace) le retour d'une personne sur une sortie IA terminée ; false si la sortie n'existe pas. */
export async function saveFeedback(db: Queryable, body: FeedbackBody, userId: number): Promise<boolean> {
  const t = await db.query<{ id: string }>(
    `SELECT t.id FROM ai_tasks t LEFT JOIN projects p ON p.id = t.project_id
      WHERE t.id = $1 AND t.status = 'done' AND t.kind NOT IN ('probe', 'testbed') AND (t.project_id IS NULL OR NOT p.ai_opt_out)`,
    [body.task_id],
  )
  if (!t.rows[0]) return false
  // Une correction peut contenir un extrait collé : elle est masquée avant stockage.
  const correction = body.correction ? redact(body.correction, { aggressive: true }).slice(0, 4000) : null
  await db.query(
    `INSERT INTO ai_feedback (task_id, user_id, vote, correction) VALUES ($1, $2, $3, $4)
     ON CONFLICT (task_id, user_id) DO UPDATE SET vote = EXCLUDED.vote, correction = EXCLUDED.correction, created_at = now()`,
    [body.task_id, userId, body.vote, correction],
  )
  return true
}

export async function deleteFeedback(db: Queryable, taskId: string, userId: number): Promise<void> {
  await db.query('DELETE FROM ai_feedback WHERE task_id = $1 AND user_id = $2', [taskId, userId])
}

/** Retour de la personne sur une sortie, pour l'afficher à côté. */
export async function myFeedback(db: Queryable, taskId: string, userId: number): Promise<{ vote: 1 | -1, correction: string | null } | null> {
  const { rows } = await db.query<{ vote: 1 | -1, correction: string | null }>(
    'SELECT vote, correction FROM ai_feedback WHERE task_id = $1 AND user_id = $2',
    [taskId, userId],
  )
  return rows[0] ?? null
}

export interface AgreementRow {
  kind: string
  model: string | null
  votes: number
  up: number
  /** Part des 👍 (0–1), null sans vote. */
  rate: number | null
  /** Pré-tri seulement : suggestions tranchées suivies d'un tri humain. */
  triaged: number | null
  matched: number | null
  triage_rate: number | null
}

/** Accord IA/humain par tâche et par modèle, sur une période (90 jours par défaut). */
export async function agreement(db: Queryable, days = 90): Promise<AgreementRow[]> {
  const votes = await db.query<{ kind: string, model: string | null, votes: number, up: number }>(
    `SELECT t.kind, t.model, count(*)::int AS votes, count(*) FILTER (WHERE f.vote = 1)::int AS up
       FROM ai_feedback f JOIN ai_tasks t ON t.id = f.task_id
      WHERE f.created_at > now() - make_interval(days => $1)
      GROUP BY t.kind, t.model`,
    [days],
  )
  // Dernière suggestion de pré-tri par résultat, comparée au tri fait par une personne après elle.
  const triage = await db.query<{ model: string | null, triaged: number, matched: number }>(
    `WITH last AS (
       SELECT DISTINCT ON (t.subject_id) t.subject_id, t.model, t.finished_at, t.output->>'suggestion' AS suggestion
         FROM ai_tasks t
        WHERE t.kind = 'triage-finding' AND t.status = 'done' AND t.finished_at > now() - make_interval(days => $1)
        ORDER BY t.subject_id, t.finished_at DESC)
     SELECT l.model,
            count(*)::int AS triaged,
            count(*) FILTER (WHERE (l.suggestion = 'likely-false-positive' AND f.status = 'false-positive')
                               OR (l.suggestion = 'likely-true-positive' AND f.status IN ('confirmed', 'accepted', 'fixed')))::int AS matched
       FROM last l JOIN findings f ON f.id::text = l.subject_id
      WHERE l.suggestion IN ('likely-false-positive', 'likely-true-positive')
        AND f.status_by IS NOT NULL AND f.status IN ('false-positive', 'confirmed', 'accepted') AND f.status_at >= l.finished_at
      GROUP BY l.model`,
    [days],
  )
  const rows = new Map<string, AgreementRow>()
  const key = (kind: string, model: string | null) => `${kind}\u0000${model ?? ''}`
  for (const v of votes.rows) {
    rows.set(key(v.kind, v.model), { kind: v.kind, model: v.model, votes: v.votes, up: v.up, rate: v.votes ? round(v.up / v.votes) : null, triaged: null, matched: null, triage_rate: null })
  }
  for (const t of triage.rows) {
    const k = key('triage-finding', t.model)
    const row = rows.get(k) ?? { kind: 'triage-finding', model: t.model, votes: 0, up: 0, rate: null, triaged: null, matched: null, triage_rate: null }
    rows.set(k, { ...row, triaged: t.triaged, matched: t.matched, triage_rate: t.triaged ? round(t.matched / t.triaged) : null })
  }
  return [...rows.values()].sort((a, b) => a.kind.localeCompare(b.kind) || (a.model ?? '').localeCompare(b.model ?? ''))
}

function round(x: number): number {
  return Math.round(x * 1000) / 1000
}
