// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Cœur du service scanoria-ai (CLAUDE.md § 3.5, I1) : file ai_tasks
// (interactif avant précalcul), concurrence 1, délai par tâche, relances,
// disjoncteur, cache par empreintes d'entrée et de modèle, découverte des
// modèles (tâche « probe ») et banc d'essai (tâche « testbed », I23).
// 0.5 : embeddings des résultats (I7, /api/embed) et résultats semblables du
// même projet, calculés ici sur un ensemble borné.
// Le service n'écrit que dans ai_tasks, ai_cache, ai_calls et ai_embeddings.

import { createHash } from 'node:crypto'
import type { Queryable } from '../utils/db'
import type { ActiveEndpoint, AiEndpoint } from './config'
import { loadAiSettings } from './config'
import { contextFor, modelInfo, selectModels, type ModelInfo, type Selection } from './models'
import { EMBED_MAX_INPUTS, OllamaError, type ChatRequest, type ChatResult, type EmbedResult } from './ollama'
import { buildMessages, promptChars, type Locale } from './prompt'
import { COMPLETION_KINDS, EMBED_KINDS, PROMPT_VERSION, TASKS, TASK_KINDS, type TaskDefinition } from './tasks'
import { EMBED_SUITE, SUITES, scoreCase, summarize, type CaseResult } from './testbed'
import { chooseThreshold, cosine, MAX_NEIGHBOUR_POOL, nearest } from './tasks/similar'

/** Ce que le service attend d'un client Ollama (le vrai, ou un double en test). */
export interface OllamaLike {
  version: (timeoutMs?: number) => Promise<string>
  tags: (timeoutMs?: number) => Promise<{ name: string, digest: string, size: number }[]>
  show: (model: string, timeoutMs?: number) => Promise<Record<string, unknown>>
  chat: (req: ChatRequest, timeoutMs: number) => Promise<ChatResult>
  /** Embeddings (I7) ; absent d'un double de test ancien : la tâche échoue proprement. */
  embed?: (model: string, input: string[], timeoutMs: number) => Promise<EmbedResult>
}

export interface ServiceDeps {
  db: Queryable
  loadEndpoint: () => Promise<AiEndpoint>
  clientFor: (endpoint: ActiveEndpoint) => Promise<OllamaLike>
  now?: () => number
  log?: (msg: string) => void
}

export const PRIORITY = { testbed: 80, probe: 70, interactive: 50, precompute: 10 } as const
const MAX_ATTEMPTS = 4
const MAX_INVALID = 2
const PROBE_MAX_AGE_MS = 6 * 3600_000
/** Banc d'essai en erreur : la tâche reste désactivée ce temps-là, puis il est rejoué. */
const TESTBED_ERROR_HOLD_MS = 3600_000
/** Découverte en erreur : les tâches en attente échouent au lieu d'attendre sans fin. */
const PROBE_ERROR_HOLD_MS = 10 * 60_000
const MAX_MODELS = 30
/** Embeddings recalculés après un changement de modèle d'embedding, par découverte. */
export const REEMBED_BATCH = 5000

/** Modèle retenu pour une tâche : modèle d'embedding pour I7, de rédaction sinon. */
export function choiceFor(selection: Selection, kind: string) {
  return TASKS[kind]?.embed ? selection.embedding : (selection.tasks[kind] ?? null)
}

// ---- Disjoncteur -------------------------------------------------------------

export class CircuitBreaker {
  private failures = 0
  private openUntil = 0
  private backoff: number

  constructor(private readonly threshold = 3, private readonly baseMs = 30_000, private readonly maxMs = 15 * 60_000) {
    this.backoff = baseMs
  }

  canCall(now: number): boolean {
    return now >= this.openUntil
  }

  /** Millisecondes avant la prochaine tentative (0 = fermé ou demi-ouvert). */
  retryIn(now: number): number {
    return Math.max(0, this.openUntil - now)
  }

  success(): void {
    this.failures = 0
    this.openUntil = 0
    this.backoff = this.baseMs
  }

  failure(now: number): boolean {
    this.failures += 1
    if (this.failures >= this.threshold) {
      this.openUntil = now + this.backoff
      this.backoff = Math.min(this.backoff * 2, this.maxMs)
      return true
    }
    return false
  }

  get state(): 'closed' | 'open' {
    return this.openUntil > 0 ? 'open' : 'closed'
  }
}

// ---- Empreintes ----------------------------------------------------------------

/** Ordre stable, indépendant de la locale (empreinte canonique). */
function byCodePoint(a: string, b: string): number {
  if (a === b) return 0
  return a < b ? -1 : 1
}

function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    return `{${Object.keys(v as object).sort(byCodePoint).map(k => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v ?? null)
}

export function inputHash(kind: string, locale: string, input: unknown): string {
  return createHash('sha256').update(`${kind}|${locale}|v${PROMPT_VERSION}|${canonical(input)}`).digest('hex')
}

// ---- Tâches --------------------------------------------------------------------

export interface AiTaskRow {
  id: string
  kind: string
  project_id: string | null
  subject_type: string
  subject_id: string
  locale: Locale
  priority: number
  attempts: number
  context: unknown
}

export type TickResult = { state: 'idle' } | { state: 'worked', taskId: string } | { state: 'waiting', ms: number }

class InvalidOutput extends Error {}

export class AiService {
  readonly circuit = new CircuitBreaker()
  private readonly now: () => number
  private readonly log: (msg: string) => void

  constructor(private readonly deps: ServiceDeps) {
    this.now = deps.now ?? Date.now
    this.log = deps.log ?? (() => {})
  }

  /** Au démarrage : une tâche « running » est celle d'un service interrompu. */
  async recover(): Promise<number> {
    const r = await this.deps.db.query(`UPDATE ai_tasks SET status = 'queued', started_at = NULL WHERE status = 'running'`)
    return r.rowCount ?? 0
  }

  private async claim(): Promise<AiTaskRow | null> {
    const { rows } = await this.deps.db.query<AiTaskRow>(
      `UPDATE ai_tasks SET status = 'running', started_at = now(), attempts = attempts + 1
        WHERE id = (SELECT id FROM ai_tasks WHERE status = 'queued'
                     ORDER BY priority DESC, created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
        RETURNING id, kind, project_id, subject_type, subject_id, locale, priority, attempts, context`,
    )
    return rows[0] ?? null
  }

  private async finish(id: string, status: 'done' | 'error' | 'skipped', fields: { output?: unknown, error?: string, model?: string, digest?: string, hash?: string } = {}): Promise<void> {
    await this.deps.db.query(
      `UPDATE ai_tasks SET status = $2, output = $3, error = $4, model = COALESCE($5, model),
              model_digest = COALESCE($6, model_digest), input_hash = COALESCE($7, input_hash), finished_at = now()
        WHERE id = $1`,
      [id, status, fields.output === undefined ? null : JSON.stringify(fields.output), fields.error ?? null,
        fields.model ?? null, fields.digest ?? null, fields.hash ?? null],
    )
  }

  /** Remet une tâche en file sans compter la tentative (attente d'une sonde, du disjoncteur…). */
  private async requeue(id: string, countAttempt: boolean): Promise<void> {
    await this.deps.db.query(
      `UPDATE ai_tasks SET status = 'queued', started_at = NULL, attempts = attempts - $2 WHERE id = $1`,
      [id, countAttempt ? 0 : 1],
    )
  }

  private async callLog(task: AiTaskRow | null, kind: string, model: string | null, bytes: number, durationMs: number | null, outcome: string): Promise<void> {
    await this.deps.db.query(
      `INSERT INTO ai_calls (task_id, kind, project_id, model, bytes_sent, duration_ms, outcome)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [task?.id ?? null, kind, task?.project_id ?? null, model, bytes, durationMs, outcome],
    )
  }

  /** Dépose une tâche du service si aucune identique n'attend déjà. */
  async enqueueInternal(kind: 'probe' | 'testbed', subjectId: string, priority: number): Promise<void> {
    await this.deps.db.query(
      `INSERT INTO ai_tasks (kind, subject_type, subject_id, priority)
       SELECT $1, 'testbed', $2, $3
        WHERE NOT EXISTS (SELECT 1 FROM ai_tasks WHERE kind = $1 AND subject_type = 'testbed'
                            AND subject_id = $2 AND status IN ('queued', 'running'))`,
      [kind, subjectId, priority],
    )
  }

  /** Dernière découverte réussie des modèles. */
  async latestProbe(): Promise<{ selection: Selection, finishedAt: Date } | null> {
    const { rows } = await this.deps.db.query<{ output: { selection?: Selection }, finished_at: Date }>(
      `SELECT output, finished_at FROM ai_tasks WHERE kind = 'probe' AND status = 'done'
        ORDER BY finished_at DESC LIMIT 1`,
    )
    const row = rows[0]
    return row?.output?.selection ? { selection: row.output.selection, finishedAt: row.finished_at } : null
  }

  /**
   * Résultat du banc d'essai d'une tâche pour un modèle précis, ou null s'il
   * n'a pas tourné. Un banc d'essai en erreur (serveur injoignable, sorties
   * invalides répétées) compte comme échoué pendant une heure, puis il est
   * rejoué : aucune tâche n'attend indéfiniment.
   */
  async testbedPassed(kind: string, digest: string): Promise<boolean | null> {
    const { rows } = await this.deps.db.query<{ status: string, output: { passed?: boolean } | null, finished_at: Date | null }>(
      `SELECT status, output, finished_at FROM ai_tasks
        WHERE kind = 'testbed' AND subject_id = $1 AND status IN ('done', 'error') AND model_digest = $2
        ORDER BY finished_at DESC NULLS LAST LIMIT 1`,
      [kind, digest],
    )
    const row = rows[0]
    if (!row) return null
    if (row.status === 'error') return row.finished_at && this.now() - row.finished_at.getTime() < TESTBED_ERROR_HOLD_MS ? false : null
    return typeof row.output?.passed === 'boolean' ? row.output.passed : null
  }

  /** Erreur de la dernière découverte si elle est récente et qu'aucune n'a abouti depuis. */
  private async recentProbeError(): Promise<string | null> {
    const { rows } = await this.deps.db.query<{ status: string, error: string | null, finished_at: Date | null }>(
      `SELECT status, error, finished_at FROM ai_tasks WHERE kind = 'probe' AND status IN ('done', 'error')
        ORDER BY finished_at DESC NULLS LAST LIMIT 1`,
    )
    const row = rows[0]
    if (!row || row.status !== 'error' || !row.finished_at) return null
    return this.now() - row.finished_at.getTime() < PROBE_ERROR_HOLD_MS ? (row.error ?? 'network') : null
  }

  /** Lance une découverte si la dernière a plus de six heures (ou n'existe pas). */
  async ensureFreshProbe(): Promise<void> {
    const p = await this.latestProbe()
    if (!p || this.now() - p.finishedAt.getTime() > PROBE_MAX_AGE_MS) await this.enqueueInternal('probe', 'connector', PRIORITY.probe)
  }

  async tick(): Promise<TickResult> {
    const task = await this.claim()
    if (!task) return { state: 'idle' }
    try {
      const endpoint = await this.deps.loadEndpoint()
      if (!endpoint.enabled) {
        await this.finish(task.id, 'skipped', { error: 'connector-disabled' })
        return { state: 'worked', taskId: task.id }
      }
      if (!this.circuit.canCall(this.now())) {
        await this.requeue(task.id, false)
        return { state: 'waiting', ms: this.circuit.retryIn(this.now()) }
      }
      const client = await this.deps.clientFor(endpoint)
      if (task.kind === 'probe') return await this.runProbe(task, client)
      if (task.kind === 'testbed') return await this.runTestbed(task, client)
      const def = TASKS[task.kind]
      if (!def || def.subjectType !== task.subject_type) {
        await this.finish(task.id, 'skipped', { error: 'unknown-kind' })
        return { state: 'worked', taskId: task.id }
      }
      return await this.runTask(task, def, client)
    }
    catch (err) {
      this.log(`task ${task.id} (${task.kind}) failed: ${(err as Error).message}`)
      await this.finish(task.id, 'error', { error: 'internal' }).catch(() => {})
      return { state: 'worked', taskId: task.id }
    }
  }

  private async projectAllows(projectId: string | null): Promise<boolean> {
    if (!projectId) return false
    const { rows } = await this.deps.db.query<{ ai_opt_out: boolean, archived_at: Date | null }>(
      'SELECT ai_opt_out, archived_at FROM projects WHERE id = $1',
      [projectId],
    )
    return rows.length === 1 && !rows[0]!.ai_opt_out && rows[0]!.archived_at === null
  }

  /** Appel du modèle, validation zod, échappement ; journalise chaque appel. */
  private async generate<I, O>(task: AiTaskRow | null, def: TaskDefinition<I, O>, client: OllamaLike, model: { model: string, context: number | null }, locale: Locale, input: I): Promise<O> {
    const messages = buildMessages(locale, def.instruction(locale), input)
    const numCtx = contextFor(promptChars(messages), model.context)
    let result: ChatResult
    try {
      result = await client.chat({ model: model.model, messages, format: def.jsonSchema, numCtx }, def.timeoutMs)
    }
    catch (err) {
      const outcome = err instanceof OllamaError && err.kind === 'timeout' ? 'timeout' : 'error'
      await this.callLog(task, def.kind, model.model, 0, null, outcome)
      if (this.circuit.failure(this.now())) await this.callLog(task, def.kind, model.model, 0, null, 'circuit-open')
      throw err
    }
    this.circuit.success()
    let parsed: unknown
    try {
      parsed = JSON.parse(result.content)
    }
    catch {
      parsed = undefined
    }
    const valid = def.output.safeParse(parsed)
    await this.callLog(task, def.kind, model.model, result.bytesSent, result.durationMs, valid.success ? 'ok' : 'invalid-output')
    if (!valid.success) throw new InvalidOutput('invalid output')
    return def.finalize(valid.data, input)
  }

  private async runTask(task: AiTaskRow, def: TaskDefinition, client: OllamaLike): Promise<TickResult> {
    // Tâche transverse (I17) : sans projet ; sa lecture écarte d'elle-même les projets exclus.
    const scoped = def.projectScoped !== false
    if (scoped ? !(await this.projectAllows(task.project_id)) : task.project_id !== null) {
      await this.finish(task.id, 'skipped', { error: 'opt-out' })
      return { state: 'worked', taskId: task.id }
    }
    const probe = await this.latestProbe()
    if (!probe) {
      const probeError = await this.recentProbeError()
      if (probeError) {
        await this.finish(task.id, 'error', { error: probeError })
        return { state: 'worked', taskId: task.id }
      }
      await this.enqueueInternal('probe', 'connector', PRIORITY.probe)
      await this.requeue(task.id, false)
      return { state: 'waiting', ms: 0 }
    }
    const choice = choiceFor(probe.selection, def.kind)
    if (!choice) {
      // I7 sans modèle d'embedding : masquée et signalée, jamais remplacée par autre chose.
      await this.finish(task.id, def.embed ? 'skipped' : 'error', { error: def.embed ? 'no-embedding-model' : 'no-model' })
      return { state: 'worked', taskId: task.id }
    }
    const tb = await this.testbedPassed(def.kind, choice.digest)
    if (tb === null) {
      await this.enqueueInternal('testbed', def.kind, PRIORITY.testbed)
      await this.requeue(task.id, false)
      return { state: 'waiting', ms: 0 }
    }
    if (!tb) {
      await this.finish(task.id, 'skipped', { error: 'disabled-by-testbed', model: choice.model, digest: choice.digest })
      return { state: 'worked', taskId: task.id }
    }
    const input = await def.load(this.deps.db, { projectId: task.project_id, subjectId: task.subject_id, context: task.context })
    if (input === null) {
      await this.finish(task.id, 'skipped', { error: 'subject-missing' })
      return { state: 'worked', taskId: task.id }
    }
    if (def.embed) return await this.runEmbed(task, def, client, choice, def.embed(input))
    const hash = inputHash(def.kind, task.locale, input)
    const cached = await this.deps.db.query<{ output: unknown }>(
      'SELECT output FROM ai_cache WHERE kind = $1 AND input_hash = $2 AND model_digest = $3 AND locale = $4',
      [def.kind, hash, choice.digest, task.locale],
    )
    if (cached.rows[0]) {
      await this.finish(task.id, 'done', { output: cached.rows[0].output, model: choice.model, digest: choice.digest, hash })
      return { state: 'worked', taskId: task.id }
    }
    try {
      const output = await this.generate(task, def, client, choice, task.locale, input)
      await this.deps.db.query(
        `INSERT INTO ai_cache (kind, input_hash, model_digest, locale, output) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT DO NOTHING`,
        [def.kind, hash, choice.digest, task.locale, JSON.stringify(output)],
      )
      await this.finish(task.id, 'done', { output, model: choice.model, digest: choice.digest, hash })
      return { state: 'worked', taskId: task.id }
    }
    catch (err) {
      return await this.failed(task, err, choice, hash)
    }
  }

  private async failed(task: AiTaskRow, err: unknown, choice: { model: string, digest: string }, hash?: string): Promise<TickResult> {
    const invalid = err instanceof InvalidOutput
    const limit = invalid ? MAX_INVALID : MAX_ATTEMPTS
    if (task.attempts < limit) {
      await this.requeue(task.id, true)
      return { state: 'waiting', ms: invalid ? 0 : this.circuit.retryIn(this.now()) || Math.min(60_000, 2 ** task.attempts * 1000) }
    }
    await this.finish(task.id, 'error', {
      error: invalid ? 'invalid-output' : err instanceof OllamaError ? err.kind : 'internal',
      model: choice.model, digest: choice.digest, hash,
    })
    return { state: 'worked', taskId: task.id }
  }

  /** Un appel /api/embed journalisé, sous le disjoncteur. */
  private async embedCall(task: AiTaskRow | null, kind: string, client: OllamaLike, model: string, input: string[], timeoutMs: number): Promise<number[][]> {
    if (!client.embed) throw new OllamaError('protocol', 'embed not supported')
    let r: EmbedResult
    try {
      r = await client.embed(model, input, timeoutMs)
    }
    catch (err) {
      const outcome = err instanceof OllamaError && err.kind === 'timeout' ? 'timeout' : err instanceof OllamaError && err.kind === 'protocol' ? 'invalid-output' : 'error'
      await this.callLog(task, kind, model, 0, null, outcome)
      if (outcome !== 'invalid-output' && this.circuit.failure(this.now())) await this.callLog(task, kind, model, 0, null, 'circuit-open')
      if (outcome === 'invalid-output') throw new InvalidOutput('invalid embeddings')
      throw err
    }
    this.circuit.success()
    await this.callLog(task, kind, model, r.bytesSent, r.durationMs, 'ok')
    return r.embeddings
  }

  /** Seuil de similarité fixé par le dernier banc d'essai réussi du modèle d'embedding. */
  private async similarityThreshold(digest: string): Promise<number | null> {
    const { rows } = await this.deps.db.query<{ output: { similarity_threshold?: unknown } | null }>(
      `SELECT output FROM ai_tasks WHERE kind = 'testbed' AND subject_id = 'embed-finding' AND status = 'done' AND model_digest = $1
        ORDER BY finished_at DESC LIMIT 1`,
      [digest],
    )
    const t = rows[0]?.output?.similarity_threshold
    return typeof t === 'number' && t > 0 && t < 1 ? t : null
  }

  /**
   * I7 : embedding d'un résultat (réutilisé si l'entrée et le modèle n'ont pas
   * changé), puis résultats semblables du même projet, ouverts, au-dessus du
   * seuil du banc d'essai. Rien d'un autre projet n'est lu.
   */
  private async runEmbed(task: AiTaskRow, def: TaskDefinition, client: OllamaLike, choice: { model: string, digest: string }, text: string): Promise<TickResult> {
    const hash = inputHash(def.kind, 'any', text)
    const known = await this.deps.db.query<{ vector: number[] }>(
      'SELECT vector FROM ai_embeddings WHERE finding_id = $1 AND model_digest = $2 AND input_hash = $3',
      [task.subject_id, choice.digest, hash],
    )
    let vector = known.rows[0]?.vector
    if (!vector) {
      try {
        vector = (await this.embedCall(task, def.kind, client, choice.model, [text], def.timeoutMs))[0]!
      }
      catch (err) {
        return await this.failed(task, err, choice, hash)
      }
      await this.deps.db.query(
        `INSERT INTO ai_embeddings (finding_id, model_digest, input_hash, vector) VALUES ($1, $2, $3, $4::real[])
         ON CONFLICT (finding_id, model_digest) DO UPDATE SET input_hash = EXCLUDED.input_hash, vector = EXCLUDED.vector, created_at = now()`,
        [task.subject_id, choice.digest, hash, vector],
      )
    }
    const threshold = await this.similarityThreshold(choice.digest)
    const pool = threshold === null
      ? []
      : (await this.deps.db.query<{ id: string, vector: number[] }>(
          `SELECT e.finding_id AS id, e.vector FROM ai_embeddings e JOIN findings f ON f.id = e.finding_id
            WHERE f.project_id = $1 AND e.model_digest = $2 AND e.finding_id <> $3 AND f.status <> 'fixed'
            ORDER BY e.created_at DESC, e.finding_id LIMIT $4`,
          [task.project_id, choice.digest, task.subject_id, MAX_NEIGHBOUR_POOL],
        )).rows
    const output = { dims: vector.length, threshold, similar: threshold === null ? [] : nearest(vector, pool, threshold) }
    await this.finish(task.id, 'done', { output, model: choice.model, digest: choice.digest, hash })
    return { state: 'worked', taskId: task.id }
  }

  /**
   * Changement de modèle d'embedding : les embeddings faits avec un autre
   * modèle sont recalculés, par lots, à basse priorité (tâches remises en file).
   */
  private async requeueStaleEmbeddings(digest: string): Promise<number> {
    const r = await this.deps.db.query(
      `UPDATE ai_tasks SET status = 'queued', attempts = 0, started_at = NULL, finished_at = NULL
        WHERE id IN (SELECT id FROM ai_tasks WHERE kind = ANY($1::text[]) AND status IN ('done', 'skipped', 'error')
                       AND model_digest IS NOT NULL AND model_digest <> $2
                       AND NOT EXISTS (SELECT 1 FROM ai_tasks n WHERE n.kind = ai_tasks.kind AND n.subject_id = ai_tasks.subject_id
                                         AND (n.status IN ('queued', 'running') OR n.model_digest = $2))
                     ORDER BY finished_at DESC NULLS LAST LIMIT $3)`,
      [EMBED_KINDS, digest, REEMBED_BATCH],
    )
    return r.rowCount ?? 0
  }

  /** Banc d'essai du modèle d'embedding (I23) : précision sur des paires connues, seuil choisi. */
  private async runEmbedTestbed(task: AiTaskRow, client: OllamaLike, choice: { model: string, digest: string }): Promise<TickResult> {
    const suite = EMBED_SUITE
    const texts = [...new Set(suite.pairs.flatMap(p => [p.a, p.b]))]
    const vectors = new Map<string, number[]>()
    try {
      for (let i = 0; i < texts.length; i += EMBED_MAX_INPUTS) {
        const batch = texts.slice(i, i + EMBED_MAX_INPUTS)
        const out = await this.embedCall(task, 'embed-finding', client, choice.model, batch, 120_000)
        batch.forEach((t, j) => vectors.set(t, out[j]!))
      }
    }
    catch (err) {
      if (!(err instanceof InvalidOutput)) return await this.failed(task, err, choice)
      const cases: CaseResult[] = suite.pairs.map(p => ({ id: p.id, ok: false, reason: 'invalid-output' }))
      await this.finish(task.id, 'done', {
        output: { kind: suite.kind, score: 0, threshold: suite.threshold, passed: false, cases, similarity_threshold: null, model: choice.model, digest: choice.digest },
        model: choice.model, digest: choice.digest,
      })
      return { state: 'worked', taskId: task.id }
    }
    const scored = suite.pairs.map(p => ({ id: p.id, similar: p.similar, score: cosine(vectors.get(p.a)!, vectors.get(p.b)!) }))
    const best = chooseThreshold(scored)
    const cases: CaseResult[] = scored.map(s => ({ id: s.id, ok: (s.score >= best.threshold) === s.similar, reason: (s.score >= best.threshold) === s.similar ? 'ok' : 'misclassified' }))
    const passed = best.accuracy >= suite.threshold
    await this.finish(task.id, 'done', {
      output: { kind: suite.kind, score: best.accuracy, threshold: suite.threshold, passed, cases, similarity_threshold: best.threshold, dims: vectors.get(texts[0]!)?.length ?? null, model: choice.model, digest: choice.digest },
      model: choice.model, digest: choice.digest,
    })
    if (!passed) this.log(`testbed failed for embed-finding on ${choice.model}: accuracy ${best.accuracy}`)
    return { state: 'worked', taskId: task.id }
  }

  /** Découverte des modèles et choix par tâche ; banc d'essai lancé pour tout modèle nouveau. */
  private async runProbe(task: AiTaskRow, client: OllamaLike): Promise<TickResult> {
    const started = this.now()
    let version: string
    let models: ModelInfo[]
    try {
      version = await client.version()
      const latency = this.now() - started
      const tags = (await client.tags()).slice(0, MAX_MODELS)
      models = []
      for (const t of tags) models.push(modelInfo(t.name, t.digest, await client.show(t.name)))
      await this.callLog(task, 'probe', null, 0, latency, 'ok')
      this.circuit.success()
      const settings = await loadAiSettings(this.deps.db)
      const selection = selectModels(models, COMPLETION_KINDS, settings.models)
      await this.finish(task.id, 'done', {
        output: { version, latency_ms: latency, models, selection, checked_at: new Date(this.now()).toISOString() },
      })
      for (const kind of TASK_KINDS) {
        const c = choiceFor(selection, kind)
        if (c && (await this.testbedPassed(kind, c.digest)) === null) await this.enqueueInternal('testbed', kind, PRIORITY.testbed)
      }
      if (selection.embedding) {
        const n = await this.requeueStaleEmbeddings(selection.embedding.digest)
        if (n) this.log(`${n} embedding(s) queued again for ${selection.embedding.model}`)
      }
      return { state: 'worked', taskId: task.id }
    }
    catch (err) {
      const outcome = err instanceof OllamaError && err.kind === 'timeout' ? 'timeout' : 'error'
      await this.callLog(task, 'probe', null, 0, null, outcome)
      if (this.circuit.failure(this.now())) await this.callLog(task, 'probe', null, 0, null, 'circuit-open')
      await this.finish(task.id, 'error', { error: err instanceof OllamaError ? err.kind : 'internal' })
      return { state: 'worked', taskId: task.id }
    }
  }

  /** Banc d'essai d'une tâche sur le modèle retenu (I23). */
  private async runTestbed(task: AiTaskRow, client: OllamaLike): Promise<TickResult> {
    const def = TASKS[task.subject_id]
    const probe = await this.latestProbe()
    if (def?.embed) {
      const emb = probe?.selection.embedding
      if (!emb) {
        await this.finish(task.id, 'skipped', { error: 'no-embedding-model' })
        return { state: 'worked', taskId: task.id }
      }
      return await this.runEmbedTestbed(task, client, emb)
    }
    const suite = SUITES[task.subject_id]
    const choice = probe?.selection.tasks[task.subject_id]
    if (!def || !suite || !choice) {
      await this.finish(task.id, 'skipped', { error: def && suite ? 'no-model' : 'unknown-kind' })
      return { state: 'worked', taskId: task.id }
    }
    const cases: CaseResult[] = []
    for (const c of suite.cases) {
      try {
        const out = await this.generate(task, def, client, choice, 'fr', c.input)
        cases.push(scoreCase(c, out))
      }
      catch (err) {
        if (!(err instanceof InvalidOutput)) {
          // Serveur indisponible : le banc d'essai n'est pas concluant, il sera rejoué.
          return await this.failed(task, err, choice)
        }
        cases.push(scoreCase(c, null))
      }
    }
    const result = summarize(suite, cases)
    await this.finish(task.id, 'done', { output: { ...result, model: choice.model, digest: choice.digest }, model: choice.model, digest: choice.digest })
    if (!result.passed) this.log(`testbed failed for ${suite.kind} on ${choice.model}: score ${result.score}`)
    return { state: 'worked', taskId: task.id }
  }
}
