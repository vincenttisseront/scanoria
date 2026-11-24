// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Côté console du connecteur IA (CLAUDE.md § 3.5) : état affiché sur la page
// Système › IA, demandes d'explication et lecture des sorties. La console
// n'appelle jamais Ollama : elle lit ce que le helper et scanoria-ai publient,
// et dépose des tâches dans ai_tasks.

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { AI_URL_RE, CERT_PEM_RE } from '#shared/schemas'
import { aiPaths, loadAiSettings, loadCheckStatus, loadEndpoint, ModelOverrides, type AiPaths } from './config'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import { TASK_KINDS, TASKS } from './tasks'
import { SUITES } from './testbed'

export const AI_TASK_KINDS = TASK_KINDS

/** Corps de POST /api/ai/connector : l'adresse est la seule saisie obligatoire. */
export const ConnectorBody = z.strictObject({
  url: z.string().min(8).max(300).regex(AI_URL_RE),
  allow_insecure: z.boolean().optional(),
  /** Nouveau jeton (chaîne), retrait (null), ou jeton actuel conservé (absent). */
  token: z.string().min(8).max(4096).regex(/^[\x21-\x7E]+$/).nullable().optional(),
  ca_pem: z.string().min(64).max(16384).regex(CERT_PEM_RE).nullable().optional(),
  /** Modale d'activation lue et confirmée (sortie de données, § 3.5). */
  confirmed: z.literal(true),
}).refine(b => !(b.url.startsWith('http:') && typeof b.token === 'string'), { message: 'token requires https', path: ['token'] })
  .refine(b => !b.url.startsWith('http:') || b.allow_insecure === true, { message: 'http requires allow_insecure', path: ['allow_insecure'] })
export type ConnectorBody = z.infer<typeof ConnectorBody>

export const ModelsBody = z.strictObject({
  models: z.partialRecord(z.enum(TASK_KINDS as [string, ...string[]]), z.string().min(1).max(200).nullable()),
})

export const ExplainBody = z.strictObject({
  kind: z.enum(TASK_KINDS as [string, ...string[]]),
  subject_id: z.uuid(),
  locale: z.enum(['fr', 'en']).optional(),
})

export const OutputQuery = z.strictObject({
  kind: z.enum(TASK_KINDS as [string, ...string[]]),
  subject_id: z.uuid(),
  locale: z.enum(['fr', 'en']).optional(),
})

interface TaskRow {
  id: string
  status: string
  output: unknown
  error: string | null
  model: string | null
  model_digest: string | null
  locale: string
  created_at: Date
  finished_at: Date | null
}

/** Projet du sujet d'une tâche (résultat ou analyse), pour le cloisonnement. */
export async function subjectProject(db: Queryable, kind: string, subjectId: string): Promise<string | null> {
  const def = TASKS[kind]
  if (!def) return null
  const table = def.subjectType === 'finding' ? 'findings' : 'scans'
  const { rows } = await db.query<{ project_id: string }>(`SELECT project_id FROM ${table} WHERE id = $1`, [subjectId])
  return rows[0]?.project_id ?? null
}

/** Demande interactive (prioritaire sur les précalculs). */
export async function requestExplanation(db: Queryable, body: z.infer<typeof ExplainBody>, userId: number, userLocale: 'fr' | 'en') {
  const projectId = await subjectProject(db, body.kind, body.subject_id)
  if (!projectId) return { found: false as const }
  const def = TASKS[body.kind]!
  const taskId = await enqueueAiTask(db, {
    kind: body.kind, subjectType: def.subjectType, subjectId: body.subject_id, projectId,
    locale: body.locale ?? userLocale, priority: AI_PRIORITY.interactive, requestedBy: userId,
  })
  return { found: true as const, task_id: taskId }
}

/** Dernière sortie d'une tâche pour un sujet (langue demandée, sinon l'autre). */
export async function latestOutput(db: Queryable, q: z.infer<typeof OutputQuery>, userLocale: 'fr' | 'en') {
  const enabled = await connectorEnabled()
  const locale = q.locale ?? userLocale
  const projectId = await subjectProject(db, q.kind, q.subject_id)
  if (!projectId) return null
  const optOut = (await db.query<{ ai_opt_out: boolean }>('SELECT ai_opt_out FROM projects WHERE id = $1', [projectId])).rows[0]?.ai_opt_out ?? false
  const { rows } = await db.query<TaskRow>(
    `SELECT id, status, output, error, model, model_digest, locale, created_at, finished_at FROM ai_tasks
      WHERE kind = $1 AND subject_id = $2 AND project_id = $3
      ORDER BY (status = 'done') DESC, (locale = $4) DESC, created_at DESC LIMIT 1`,
    [q.kind, q.subject_id, projectId, locale],
  )
  // Sans connecteur, ou pour un projet exclu, la page reste celle d'une appliance sans IA.
  const t = enabled && !optOut ? rows[0] : undefined
  const current = t ? await currentDigest(db, q.kind) : null
  return {
    enabled,
    opt_out: optOut,
    task: t
      ? {
          id: t.id,
          status: t.status,
          locale: t.locale,
          error: t.error,
          output: t.status === 'done' ? t.output : null,
          model: t.model,
          model_digest: t.model_digest,
          generated_at: t.finished_at?.toISOString() ?? null,
          /** Produite par un autre modèle que celui retenu aujourd'hui. */
          stale: t.status === 'done' && current !== null && t.model_digest !== current,
        }
      : null,
  }
}

/** Empreinte du modèle retenu pour une tâche par la dernière découverte. */
export async function currentDigest(db: Queryable, kind: string): Promise<string | null> {
  const { rows } = await db.query<{ digest: string | null }>(
    `SELECT output->'selection'->'tasks'->$1->>'digest' AS digest FROM ai_tasks
      WHERE kind = 'probe' AND status = 'done' ORDER BY finished_at DESC LIMIT 1`,
    [kind],
  )
  return rows[0]?.digest ?? null
}

/** Découverte des modèles demandée depuis la console (après un changement de choix). */
export async function requestProbe(db: Queryable): Promise<boolean> {
  if (!(await connectorEnabled(0))) return false
  await db.query(
    `INSERT INTO ai_tasks (kind, subject_type, subject_id, priority)
     SELECT 'probe', 'testbed', 'connector', 70
      WHERE NOT EXISTS (SELECT 1 FROM ai_tasks WHERE kind = 'probe' AND status IN ('queued', 'running'))`,
  )
  return true
}

export async function saveSetting(db: Queryable, key: string, value: unknown, userId: number | null): Promise<void> {
  if (value === null) {
    await db.query('DELETE FROM appliance_settings WHERE key = $1', [key])
    return
  }
  await db.query(
    `INSERT INTO appliance_settings (key, value, updated_at, updated_by) VALUES ($1, $2, now(), $3)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
    [key, JSON.stringify(value), userId],
  )
}

export async function setModelOverrides(db: Queryable, models: Partial<Record<string, string | null>>, userId: number): Promise<Record<string, string>> {
  const current = (await loadAiSettings(db)).models
  const merged: Record<string, string | null | undefined> = { ...current, ...models }
  const next = Object.fromEntries(Object.entries(merged).filter((e): e is [string, string] => typeof e[1] === 'string'))
  const parsed = ModelOverrides.parse(next)
  await saveSetting(db, 'ai.models', Object.keys(parsed).length ? parsed : null, userId)
  return parsed
}

export async function recentCalls(db: Queryable, limit = 100) {
  const { rows } = await db.query(
    `SELECT c.id, c.kind, c.model, c.bytes_sent, c.duration_ms, c.outcome, c.at, p.slug AS project
       FROM ai_calls c LEFT JOIN projects p ON p.id = c.project_id
      ORDER BY c.at DESC, c.id DESC LIMIT $1`,
    [Math.max(1, Math.min(500, limit))],
  )
  return rows
}

/** Tout ce que la page Système › IA affiche, et pourquoi chaque choix a été fait. */
export async function aiStatus(db: Queryable, paths: AiPaths = aiPaths()) {
  const [endpoint, check, settings] = await Promise.all([loadEndpoint(paths.endpointFile), loadCheckStatus(paths.statusFile), loadAiSettings(db)])
  const probeRow = (await db.query<{ status: string, output: Record<string, unknown> | null, error: string | null, finished_at: Date | null }>(
    `SELECT status, output, error, finished_at FROM ai_tasks WHERE kind = 'probe' AND status IN ('done', 'error')
      ORDER BY finished_at DESC NULLS LAST LIMIT 1`,
  )).rows[0]
  const lastGood = (await db.query<{ output: Record<string, unknown>, finished_at: Date }>(
    `SELECT output, finished_at FROM ai_tasks WHERE kind = 'probe' AND status = 'done' ORDER BY finished_at DESC LIMIT 1`,
  )).rows[0]
  const testbed = (await db.query<{ subject_id: string, output: Record<string, unknown>, model: string | null, model_digest: string | null, finished_at: Date }>(
    `SELECT DISTINCT ON (subject_id) subject_id, output, model, model_digest, finished_at FROM ai_tasks
      WHERE kind = 'testbed' AND status = 'done' ORDER BY subject_id, finished_at DESC`,
  )).rows
  const calls = (await db.query<{ outcome: string, duration_ms: number | null, at: Date }>(
    `SELECT outcome, duration_ms, at FROM ai_calls ORDER BY at DESC, id DESC LIMIT 20`,
  )).rows
  const queue = (await db.query<{ status: string, n: number }>(
    `SELECT status, count(*)::int AS n FROM ai_tasks WHERE status IN ('queued', 'running') GROUP BY status`,
  )).rows
  const latencies = calls.filter(c => c.outcome === 'ok' && c.duration_ms !== null).map(c => c.duration_ms!)
  const lastFailure = calls.find(c => c.outcome !== 'ok' && c.outcome !== 'invalid-output')
  const failuresInRow = calls.findIndex(c => c.outcome === 'ok' || c.outcome === 'invalid-output')
  const circuitOpen = calls[0]?.outcome === 'circuit-open' || (failuresInRow === -1 ? calls.length >= 3 : failuresInRow >= 3)
  const selection = (lastGood?.output?.selection ?? null) as { tasks: Record<string, unknown>, embedding: unknown } | null
  const tasks = TASK_KINDS.map((kind) => {
    const choice = (selection?.tasks?.[kind] ?? null) as { model: string, digest: string, reason: string } | null
    const tb = testbed.find(r => r.subject_id === kind)
    const tbCurrent = tb && choice && tb.model_digest === choice.digest ? tb : null
    return {
      kind,
      model: choice,
      override: settings.models[kind] ?? null,
      testbed: tbCurrent
        ? { score: tbCurrent.output.score, threshold: tbCurrent.output.threshold, passed: tbCurrent.output.passed, cases: tbCurrent.output.cases, at: tbCurrent.finished_at.toISOString() }
        : null,
      threshold: SUITES[kind]?.threshold ?? null,
      state: !endpoint.enabled ? 'off' : !choice ? 'no-model' : !tbCurrent ? 'testing' : tbCurrent.output.passed ? 'active' : 'disabled',
    }
  })
  const { url, host, port, addresses, insecure, token, ca, pinned_at } = endpoint.enabled
    ? endpoint
    : { url: null, host: null, port: null, addresses: [], insecure: false, token: false, ca: false, pinned_at: null }
  return {
    enabled: endpoint.enabled,
    endpoint: { url, host, port, addresses, insecure, token, ca, pinned_at },
    token_stored: settings.tokenCredentialId !== null,
    check,
    probe: probeRow
      ? { status: probeRow.status, error: probeRow.error, at: probeRow.finished_at?.toISOString() ?? null, version: (lastGood?.output?.version as string | undefined) ?? null }
      : null,
    models: (lastGood?.output?.models ?? []) as unknown[],
    embedding: selection?.embedding ?? null,
    tasks,
    circuit: { state: endpoint.enabled && circuitOpen ? 'open' : 'closed', last_failure_at: lastFailure?.at.toISOString() ?? null },
    latency_ms: latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null,
    queue: { queued: queue.find(q => q.status === 'queued')?.n ?? 0, running: queue.find(q => q.status === 'running')?.n ?? 0 },
  }
}
