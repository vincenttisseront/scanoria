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
import { COMPLETION_KINDS, TASK_KINDS, TASKS } from './tasks'
import { EMBED_SUITE, SUITES } from './testbed'
import { UUID_RE } from './task-kit'
import { DEFAULT_KEY, EMBEDDING_KEY } from './models'
import { failedModules, proposeTimeout, type TimeoutProposal } from './tasks/diagnose'
import { ruleKey } from './tasks/translate'
import { ADMIN_ONLY_KINDS, myFeedback } from './feedback'
import { loadTimeoutOverrides, TimeoutOverrides } from './overrides'

export { loadTimeoutOverrides } from './overrides'

export const AI_TASK_KINDS = TASK_KINDS

/** Corps de POST /api/ai/connector : l'adresse est la seule saisie obligatoire. */
export const ConnectorBody = z.strictObject({
  url: z.string().min(8).max(300).regex(AI_URL_RE),
  allow_insecure: z.boolean().optional(),
  /** Nouveau jeton (chaîne), retrait (null), ou jeton actuel conservé (absent). */
  token: z.string().min(8).max(4096).regex(/^[\x21-\x7E]+$/).nullable().optional(),
  ca_pem: z.string().min(64).max(16384).regex(CERT_PEM_RE).nullable().optional(),
  /** https seulement, sans AC : certificat du serveur accepté sans vérification (défaut : vérifié). */
  skip_tls_verify: z.boolean().optional(),
  /** Modale d'activation lue et confirmée (sortie de données, § 3.5). */
  confirmed: z.literal(true),
}).refine(b => !(b.url.startsWith('http:') && typeof b.token === 'string'), { message: 'token requires https', path: ['token'] })
  .refine(b => !b.url.startsWith('http:') || b.allow_insecure === true, { message: 'http requires allow_insecure', path: ['allow_insecure'] })
  .refine(b => !(b.skip_tls_verify && b.url.startsWith('http:')), { message: 'skip_tls_verify requires https', path: ['skip_tls_verify'] })
  .refine(b => !(b.skip_tls_verify && b.ca_pem), { message: 'skip_tls_verify excludes ca_pem', path: ['skip_tls_verify'] })
export type ConnectorBody = z.infer<typeof ConnectorBody>

/**
 * Choix forcé : « default » (toutes les tâches de rédaction), « embedding »
 * (I7) ou une tâche de rédaction précise ; null rend au choix automatique.
 * Un nom libre est accepté (saisie de secours quand la liste est vide) : tant
 * qu'il est absent du serveur, le choix automatique s'applique et le dit.
 */
export const MODEL_KEYS = [DEFAULT_KEY, EMBEDDING_KEY, ...COMPLETION_KINDS] as [string, ...string[]]
export const ModelsBody = z.strictObject({
  models: z.partialRecord(z.enum(MODEL_KEYS), z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/).nullable()),
})

/** Identifiant de sujet conforme à la tâche (uuid, ou clé outil:version:règle pour I17). */
const subjectFits = (b: { kind: string, subject_id: string }) => (TASKS[b.kind]?.subjectPattern ?? UUID_RE).test(b.subject_id)
const SUBJECT_ISSUE = { message: 'subject_id does not match the task', path: ['subject_id'] }
/** I16 (0.6) : le diagnostic de l'appliance a ses propres routes, réservées aux administrateurs (/api/ai/appliance/…). */
const notAdminOnly = (b: { kind: string }) => !ADMIN_ONLY_KINDS.includes(b.kind)
const ADMIN_ONLY_ISSUE = { message: 'use /api/ai/appliance/diagnosis', path: ['kind'] }

export const ExplainBody = z.strictObject({
  kind: z.enum(COMPLETION_KINDS as [string, ...string[]]),
  subject_id: z.string().min(1).max(400),
  locale: z.enum(['fr', 'en']).optional(),
}).refine(subjectFits, SUBJECT_ISSUE).refine(notAdminOnly, ADMIN_ONLY_ISSUE)

export const OutputQuery = z.strictObject({
  kind: z.enum(COMPLETION_KINDS as [string, ...string[]]),
  subject_id: z.string().min(1).max(400),
  locale: z.enum(['fr', 'en']).optional(),
}).refine(subjectFits, SUBJECT_ISSUE).refine(notAdminOnly, ADMIN_ONLY_ISSUE)

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

/** Sujet transverse (I17) : aucun projet, toute personne connectée peut lire la traduction d'une règle. */
export const GLOBAL_SUBJECT = 'global' as const

/** Projet du sujet d'une tâche (résultat ou analyse), pour le cloisonnement ; GLOBAL_SUBJECT pour une règle. */
export async function subjectProject(db: Queryable, kind: string, subjectId: string): Promise<string | null> {
  const def = TASKS[kind]
  if (!def || !(def.subjectPattern ?? UUID_RE).test(subjectId)) return null
  if (def.projectScoped === false) return GLOBAL_SUBJECT
  // I19 (0.8) : le sujet d'une suggestion de gate est le projet lui-même.
  if (def.subjectType === 'gate') {
    const p = await db.query<{ id: string }>('SELECT id FROM projects WHERE id = $1', [subjectId])
    return p.rows[0]?.id ?? null
  }
  // 0.8 (A, I6) : sujet « release » = rapport de release, identifié par son analyse.
  const SOURCES: Record<string, string> = { finding: 'findings WHERE id', scan: 'scans WHERE id', release: 'release_reports WHERE scan_id' }
  const source = SOURCES[def.subjectType] ?? null
  if (!source) return null
  const { rows } = await db.query<{ project_id: string }>(`SELECT project_id FROM ${source} = $1`, [subjectId])
  return rows[0]?.project_id ?? null
}

/** Demande interactive (prioritaire sur les précalculs). */
export async function requestExplanation(db: Queryable, body: z.infer<typeof ExplainBody>, userId: number, userLocale: 'fr' | 'en') {
  const projectId = await subjectProject(db, body.kind, body.subject_id)
  if (!projectId) return { found: false as const }
  const def = TASKS[body.kind]!
  const taskId = await enqueueAiTask(db, {
    kind: body.kind, subjectType: def.subjectType, subjectId: body.subject_id, projectId: projectId === GLOBAL_SUBJECT ? null : projectId,
    locale: body.locale ?? userLocale, priority: AI_PRIORITY.interactive, requestedBy: userId,
  })
  return { found: true as const, task_id: taskId }
}

/** Dernière sortie d'une tâche pour un sujet (langue demandée, sinon l'autre). */
export async function latestOutput(db: Queryable, q: z.infer<typeof OutputQuery>, userLocale: 'fr' | 'en', userId: number | null = null) {
  const enabled = await connectorEnabled()
  const locale = q.locale ?? userLocale
  const projectId = await subjectProject(db, q.kind, q.subject_id)
  if (!projectId) return null
  const global = projectId === GLOBAL_SUBJECT
  const optOut = global ? false : (await db.query<{ ai_opt_out: boolean }>('SELECT ai_opt_out FROM projects WHERE id = $1', [projectId])).rows[0]?.ai_opt_out ?? false
  const { rows } = await db.query<TaskRow>(
    `SELECT id, status, output, error, model, model_digest, locale, created_at, finished_at FROM ai_tasks
      WHERE kind = $1 AND subject_id = $2 AND project_id IS NOT DISTINCT FROM $3
      ORDER BY (status = 'done') DESC, (locale = $4) DESC, created_at DESC LIMIT 1`,
    [q.kind, q.subject_id, global ? null : projectId, locale],
  )
  // Sans connecteur, ou pour un projet exclu, la page reste celle d'une appliance sans IA.
  const t = enabled && !optOut ? rows[0] : undefined
  const current = t ? await currentDigest(db, q.kind) : null
  const feedback = t && t.status === 'done' && userId !== null ? await myFeedback(db, t.id, userId) : null
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
          /** I24 : retour de la personne qui lit, s'il existe. */
          feedback,
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
  // Fusion atomique : deux enregistrements simultanés de clés différentes ne s'écrasent pas.
  const set = Object.fromEntries(Object.entries(models).filter((e): e is [string, string] => typeof e[1] === 'string'))
  const removed = Object.entries(models).filter(e => e[1] === null).map(e => e[0])
  ModelOverrides.parse(set)
  const { rows } = await db.query<{ value: unknown }>(
    `INSERT INTO appliance_settings (key, value, updated_at, updated_by) VALUES ('ai.models', $1::jsonb, now(), $3)
     ON CONFLICT (key) DO UPDATE SET value = (appliance_settings.value || $1::jsonb) - $2::text[], updated_at = now(), updated_by = EXCLUDED.updated_by
     RETURNING value`,
    [JSON.stringify(set), removed, userId],
  )
  const parsed = ModelOverrides.safeParse(rows[0]?.value ?? {})
  return parsed.success ? parsed.data : {}
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
  const pendingRow = (await db.query<{ n: number, stalled: boolean }>(
    `SELECT count(*)::int AS n, coalesce(bool_and(created_at < now() - interval '2 minutes'), false) AS stalled
       FROM ai_tasks WHERE kind = 'probe' AND status IN ('queued', 'running')`,
  )).rows[0]!
  const probePending = pendingRow.n > 0
  /** Découverte en attente depuis plus de deux minutes : scanoria-ai ne la traite pas. */
  const probeStalled = probePending && pendingRow.stalled
  const latencies = calls.filter(c => c.outcome === 'ok' && c.duration_ms !== null).map(c => c.duration_ms!)
  const lastFailure = calls.find(c => c.outcome !== 'ok' && c.outcome !== 'invalid-output')
  const failuresInRow = calls.findIndex(c => c.outcome === 'ok' || c.outcome === 'invalid-output')
  const circuitOpen = calls[0]?.outcome === 'circuit-open' || (failuresInRow === -1 ? calls.length >= 3 : failuresInRow >= 3)
  const selection = (lastGood?.output?.selection ?? null) as { tasks: Record<string, unknown>, embedding: unknown } | null
  const tasks = TASK_KINDS.map((kind) => {
    const embedding = !!TASKS[kind]!.embed
    const choice = ((embedding ? selection?.embedding : selection?.tasks?.[kind]) ?? null) as { model: string, digest: string, reason: string } | null
    const tb = testbed.find(r => r.subject_id === kind)
    const tbCurrent = tb && choice && tb.model_digest === choice.digest ? tb : null
    return {
      kind,
      /** I7 : modèle d'embedding, choisi automatiquement (aucun choix forcé). */
      embedding,
      model: choice,
      override: (embedding ? settings.models[EMBEDDING_KEY] : settings.models[kind]) ?? null,
      testbed: tbCurrent
        ? {
            score: tbCurrent.output.score, threshold: tbCurrent.output.threshold, passed: tbCurrent.output.passed, cases: tbCurrent.output.cases, at: tbCurrent.finished_at.toISOString(),
            // I7 : seuil de similarité fixé par le banc d'essai.
            ...(embedding ? { similarity_threshold: tbCurrent.output.similarity_threshold ?? null } : {}),
          }
        : null,
      threshold: (embedding ? EMBED_SUITE.threshold : SUITES[kind]?.threshold) ?? null,
      state: !endpoint.enabled ? 'off' : !choice ? 'no-model' : !tbCurrent ? 'testing' : tbCurrent.output.passed ? 'active' : 'disabled',
    }
  })
  const { url, host, port, addresses, insecure, token, ca, pinned_at } = endpoint.enabled
    ? endpoint
    : { url: null, host: null, port: null, addresses: [], insecure: false, token: false, ca: false, pinned_at: null }
  const tls_verify = !endpoint.enabled || endpoint.tls_verify !== false
  return {
    enabled: endpoint.enabled,
    endpoint: { url, host, port, addresses, insecure, token, ca, tls_verify, pinned_at },
    token_stored: settings.tokenCredentialId !== null,
    check,
    probe: probeRow
      ? {
          status: probeRow.status, error: probeRow.error, at: probeRow.finished_at?.toISOString() ?? null,
          version: (lastGood?.output?.version as string | undefined) ?? null, pending: probePending, stalled: probeStalled,
        }
      : (probePending ? { status: 'queued', error: null, at: null, version: null, pending: true, stalled: probeStalled } : null),
    /** Liste de la dernière découverte réussie, et sa date (gardée si le serveur ne répond plus). */
    models: (lastGood?.output?.models ?? []) as unknown[],
    models_at: lastGood?.finished_at.toISOString() ?? null,
    embedding: selection?.embedding ?? null,
    /** Choix globaux : un modèle de rédaction pour toutes les tâches, un modèle d'embedding. */
    defaults: { generation: settings.models[DEFAULT_KEY] ?? null, embedding: settings.models[EMBEDDING_KEY] ?? null },
    tasks,
    circuit: { state: endpoint.enabled && circuitOpen ? 'open' : 'closed', last_failure_at: lastFailure?.at.toISOString() ?? null },
    latency_ms: latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null,
    queue: { queued: queue.find(q => q.status === 'queued')?.n ?? 0, running: queue.find(q => q.status === 'running')?.n ?? 0 },
  }
}

// ---- 0.4 : suggestions en lot (I3, I14), réglage proposé par un diagnostic (I15) ----

export const SuggestionsQuery = z.strictObject({
  kind: z.enum(['triage-finding', 'classify-secret']),
  ids: z.string().max(37 * 200).transform(s => [...new Set(s.split(',').filter(Boolean))]).pipe(z.array(z.uuid()).min(1).max(200)),
})

/**
 * Dernières suggestions pour une liste de résultats (liste des résultats) :
 * l'indice seul, avec le modèle. Rien sans connecteur ni pour un projet exclu.
 */
export async function latestSuggestions(db: Queryable, q: z.infer<typeof SuggestionsQuery>) {
  if (!(await connectorEnabled())) return { enabled: false, items: {} as Record<string, unknown> }
  const { rows } = await db.query<{ subject_id: string, output: Record<string, unknown>, model: string | null, model_digest: string | null }>(
    `SELECT DISTINCT ON (t.subject_id) t.subject_id, t.output, t.model, t.model_digest
       FROM ai_tasks t JOIN projects p ON p.id = t.project_id
      WHERE t.kind = $1 AND t.status = 'done' AND t.subject_type = 'finding' AND t.subject_id = ANY($2::text[]) AND NOT p.ai_opt_out
      ORDER BY t.subject_id, t.finished_at DESC`,
    [q.kind, q.ids],
  )
  const items: Record<string, { value: string, model: string | null, model_digest: string | null }> = {}
  for (const r of rows) {
    const value = q.kind === 'triage-finding' ? r.output?.suggestion : r.output?.class
    if (typeof value === 'string') items[r.subject_id] = { value, model: r.model, model_digest: r.model_digest }
  }
  return { enabled: true, items }
}

/**
 * Réglage sûr proposé pour une analyse en échec (I15) : recalculé ici depuis
 * les faits (module arrivé à son délai, délai du plan), jamais repris de la
 * sortie de l'IA ni de la demande. null s'il n'y a rien de sûr à proposer.
 */
export async function timeoutProposal(db: Queryable, scanId: string): Promise<TimeoutProposal | null> {
  const s = await db.query<{ project_id: string }>('SELECT project_id FROM scans WHERE id = $1', [scanId])
  const projectId = s.rows[0]?.project_id
  if (!projectId) return null
  const { modules } = await failedModules(db, scanId, projectId)
  const overrides = await loadTimeoutOverrides(db)
  for (const m of modules) {
    const p = proposeTimeout(m)
    // Déjà appliqué (le délai forcé couvre la proposition) : rien de plus à proposer.
    if (p && (overrides[p.module] ?? 0) < p.proposed_s) return p
  }
  return null
}

export async function applyTimeoutProposal(db: Queryable, p: TimeoutProposal, userId: number): Promise<Record<string, number>> {
  const next = { ...(await loadTimeoutOverrides(db)), [p.module]: p.proposed_s }
  await saveSetting(db, 'scan.timeout_overrides', TimeoutOverrides.parse(next), userId)
  return next
}

export const RuleKeyQuery = z.strictObject({ finding_id: z.string().regex(UUID_RE) })

/**
 * Clé de traduction (I17) de la règle d'un résultat : outil, version du module
 * de la dernière analyse qui l'a vu, règle. Calculée côté serveur, comme à
 * l'ingestion, pour que la console retrouve la traduction précalculée.
 * Aucune clé pour un secret (rien n'est traduit) ni pour un projet exclu.
 */
export async function ruleKeyOf(db: Queryable, findingId: string): Promise<{ found: boolean, key: string | null }> {
  const { rows } = await db.query<{ tool: string, rule_id: string, category: string, ai_opt_out: boolean, module_version: string | null }>(
    `SELECT f.tool, f.rule_id, f.category, p.ai_opt_out, sm.module_version
       FROM findings f JOIN projects p ON p.id = f.project_id
       LEFT JOIN scan_modules sm ON sm.scan_id = f.last_scan_id AND sm.module_id = f.tool
      WHERE f.id = $1`, [findingId])
  const f = rows[0]
  if (!f) return { found: false, key: null }
  if (f.category === 'secrets' || f.ai_opt_out) return { found: true, key: null }
  return { found: true, key: ruleKey(f.tool, f.module_version, f.rule_id) }
}
