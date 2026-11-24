// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// G14, canaris nocturnes. Le helper rejoue chaque nuit le banc d'essai F12 de
// chaque scanner installé et actif (run-canaries, minuteur nocturne) ; la
// console range chaque résultat dans canary_runs. Un module qui ne détecte
// plus un cas connu est signalé (fiche du module, tableau de bord, audit) et
// n'est jamais désactivé : c'est à une personne d'en décider (seules les
// tâches IA se désactivent seules, I23). La même nuit, les bancs d'essai IA
// déjà connus sont rejoués par scanoria-ai si le connecteur est actif.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { connectorEnabled } from '../ai/enqueue'
import { MODULE_ID_RE, MODULE_VERSION_RE, TIMESTAMP_RE } from '#shared/schemas'

/** Priorité des bancs d'essai IA nocturnes : sous toute tâche interactive ou de précalcul. */
export const NIGHTLY_AI_TESTBED_PRIORITY = 5

const canarySchema = z.object({
  module: z.string().regex(MODULE_ID_RE),
  version: z.string().regex(MODULE_VERSION_RE),
  image_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/).nullable(),
  ok: z.boolean(),
  details: z.object({
    expect: z.array(z.object({
      rule: z.string().max(255).nullable().optional(),
      category: z.string().max(64).nullable().optional(),
      min: z.number().int(),
      found: z.number().int(),
      ok: z.boolean(),
    })).max(64).default([]),
    error: z.object({ code: z.string().max(64), message: z.string().max(500), class: z.enum(['detection', 'infra']).optional() }).optional(),
  }),
  duration_ms: z.number().int().min(0).max(86_400_000),
  run_at: z.string().regex(TIMESTAMP_RE),
})
export type CanaryResult = z.infer<typeof canarySchema>

/**
 * Détection perdue (G14) : le module a tourné sans trouver le cas connu. Une
 * erreur d'infrastructure (délai, mémoire, image, runner occupé, G12) n'en est
 * pas une : elle est gardée dans l'historique, sans alerte ni audit d'échec.
 */
export function isDetectionFailure(c: { ok: boolean, details: { error?: { class?: string } } }): boolean {
  return !c.ok && c.details.error?.class !== 'infra'
}

/** Résultats run-canaries du helper pas encore rangés (console, timer ou cli). */
export async function applyCanaryResults(db: Queryable): Promise<number> {
  const r = await db.query<{ id: string, origin: string, output: { canaries?: unknown } | null }>(
    `SELECT id::text, origin, output FROM helper_requests
      WHERE type = 'run-canaries' AND status IN ('ok', 'error') AND NOT (params ? 'applied')
      ORDER BY created_at LIMIT 20`)
  let n = 0
  for (const req of r.rows) {
    await db.query(`UPDATE helper_requests SET params = params || '{"applied": true}'::jsonb WHERE id = $1`, [req.id])
    const list = Array.isArray(req.output?.canaries) ? req.output.canaries.slice(0, 200) : []
    const failed: CanaryResult[] = []
    for (const raw of list) {
      const c = canarySchema.safeParse(raw)
      if (!c.success) continue
      await db.query(
        `INSERT INTO canary_runs (module_id, module_version, image_digest, ok, details, duration_ms, run_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [c.data.module, c.data.version, c.data.image_digest, c.data.ok, JSON.stringify(c.data.details), c.data.duration_ms, c.data.run_at])
      if (isDetectionFailure(c.data)) failed.push(c.data)
      n++
    }
    for (const f of failed) {
      await writeAudit(db, {
        actor: { type: 'system' }, action: 'module.canary-failed', outcome: 'failure', targetType: 'module', targetId: f.module,
        requestId: req.id,
        details: { version: f.version, image_digest: f.image_digest, error: f.details.error?.code ?? null,
          missing: f.details.expect.filter(e => !e.ok).map(e => ({ rule: e.rule ?? e.category ?? null, min: e.min, found: e.found })) },
      })
    }
    // I23 la nuit : bancs d'essai IA déjà connus rejoués en même temps.
    if (req.origin === 'timer') await enqueueNightlyAiTestbeds(db)
  }
  return n
}

/** Bancs d'essai IA déjà passés une fois, remis en file à basse priorité ; sans effet sans connecteur. */
export async function enqueueNightlyAiTestbeds(db: Queryable): Promise<number> {
  if (!(await connectorEnabled(0))) return 0
  const r = await db.query(
    `INSERT INTO ai_tasks (kind, subject_type, subject_id, priority)
     SELECT DISTINCT 'testbed', 'testbed', t.subject_id, $1::int FROM ai_tasks t
      WHERE t.kind = 'testbed' AND t.subject_type = 'testbed'
        AND NOT EXISTS (SELECT 1 FROM ai_tasks q WHERE q.kind = 'testbed' AND q.subject_id = t.subject_id
                                                  AND q.status IN ('queued', 'running'))`, [NIGHTLY_AI_TESTBED_PRIORITY])
  return r.rowCount ?? 0
}

export interface CanaryView {
  module_id: string
  module_version: string
  image_digest: string | null
  ok: boolean
  details: CanaryResult['details']
  duration_ms: number | null
  run_at: string
}

/** Dernier canari de chaque module. */
export async function latestCanaries(db: Queryable): Promise<CanaryView[]> {
  const r = await db.query<Omit<CanaryView, 'run_at'> & { run_at: Date }>(
    `SELECT DISTINCT ON (module_id) module_id, module_version, image_digest, ok, details, duration_ms, run_at
       FROM canary_runs ORDER BY module_id, run_at DESC`)
  return r.rows.map(x => ({ ...x, run_at: x.run_at.toISOString() }))
}

export async function canaryHistory(db: Queryable, moduleId: string, limit = 14): Promise<CanaryView[]> {
  const r = await db.query<Omit<CanaryView, 'run_at'> & { run_at: Date }>(
    `SELECT module_id, module_version, image_digest, ok, details, duration_ms, run_at
       FROM canary_runs WHERE module_id = $1 ORDER BY run_at DESC LIMIT $2`, [moduleId, limit])
  return r.rows.map(x => ({ ...x, run_at: x.run_at.toISOString() }))
}
