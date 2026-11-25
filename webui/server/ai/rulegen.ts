// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I12 (0.7), côté console du générateur de règles : dépôt de la tâche
// generate-rule, test de la règle proposée dans le conteneur confiné du
// moteur, puis enregistrement dans un jeu de règles G4 confirmé par un
// administrateur humain (origin = 'ai'). L'IA ne décide rien :
// - la règle et ses exemples sont repris de la sortie de la tâche, jamais du
//   navigateur ;
// - la règle doit trouver l'exemple positif et pas le négatif ; le test est
//   rejoué au moment de l'enregistrement ;
// - seul un clic d'un administrateur humain (users.kind = 'human') enregistre,
//   et chaque enregistrement est tracé dans l'audit.
//
// Les jeux de règles (stockage, contrôles statiques, test confiné par la
// demande helper validate-ruleset) appartiennent au chantier A : ils sont
// appelés par leur contrat (webui/server/rulesets/store.ts et engine.ts),
// branché par setRulesetBackend. Sans lui, le générateur reste disponible,
// mais le test et l'enregistrement répondent « indisponible ».

import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { AI_PRIORITY, connectorEnabled, enqueueAiTask } from './enqueue'
import { findingInput, UUID_RE } from './task-kit'
import {
  boundRulegenContext, GenerateRuleOutput, MAX_SAMPLE, RULE_ENGINES, RULE_SOURCES, RULEGEN_SUBJECT_RE,
  rulegenSubjectId, type RuleEngine, type RulegenContext,
} from './tasks/rulegen'

// ---- Contrat du chantier A (jeux de règles G4) ----------------------------------

export interface RulesetSummary {
  id: string
  slug: string
  engine: string
  name: string
  latest_version: number | null
  archived_at: string | null
}

export interface RulesetTestResult {
  ok: boolean
  errors: string[]
  samples: { name: string, matches: number }[]
}

export interface RulesetBackend {
  createRuleset: (db: Queryable, a: { slug: string, engine: string, name: string, description?: string, userId: number }) => Promise<{ id: string }>
  addRulesetVersion: (db: Queryable, a: { rulesetId: string, content: string, comment?: string, origin: 'manual' | 'import' | 'ai', userId: number }) => Promise<{ version: number, sha256: string }>
  listRulesets: (db: Queryable, a: { engine?: string, includeArchived?: boolean }) => Promise<RulesetSummary[]>
  testRuleset: (db: Queryable, a: { engine: string, content: string, samples: { name: string, filename: string, content: string }[], userId: number }) => Promise<RulesetTestResult>
}

let backend: RulesetBackend | null = null

/** Branche les jeux de règles du chantier A (ou un double en test) ; null les retire. */
export function setRulesetBackend(b: RulesetBackend | null): void {
  backend = b
}

export class RulegenError extends Error {
  constructor(public readonly reason: 'unavailable' | 'not-ready' | 'not-found' | 'test-failed' | 'not-human' | 'archived' | 'engine-mismatch') {
    super(reason)
  }
}

function requireBackend(): RulesetBackend {
  if (!backend) throw new RulegenError('unavailable')
  return backend
}

// ---- Demande et lecture ----------------------------------------------------------

export const GenerateBody = z.strictObject({
  engine: z.enum(RULE_ENGINES),
  source: z.enum(RULE_SOURCES),
  finding_id: z.string().regex(UUID_RE).optional(),
  description: z.string().trim().min(3).max(1000).optional(),
  example: z.string().min(3).max(MAX_SAMPLE).optional(),
  language: z.string().regex(/^[a-z][a-z0-9+#-]{0,31}$/).optional(),
  locale: z.enum(['fr', 'en']).optional(),
}).refine(b => b.source !== 'finding' || !!b.finding_id, { message: 'finding_id required', path: ['finding_id'] })
  .refine(b => b.source !== 'example' || !!b.example, { message: 'example required', path: ['example'] })
  .refine(b => b.source !== 'phrase' || !!b.description, { message: 'description required', path: ['description'] })
export type GenerateBody = z.infer<typeof GenerateBody>

export const RuleQuery = z.strictObject({ subject_id: z.string().regex(RULEGEN_SUBJECT_RE) })
/** GET : sans subject_id, seulement l'état (connecteur, jeux de règles branchés). */
export const RuleReadQuery = z.strictObject({ subject_id: z.string().regex(RULEGEN_SUBJECT_RE).optional() })

/**
 * Contexte envoyé : le résultat choisi (masqué, sans valeur de secret) si son
 * projet accepte l'IA, l'exemple ou la description (masqués). null : résultat
 * introuvable ou projet « aucun envoi à l'IA ».
 */
export async function rulegenContext(db: Queryable, body: GenerateBody): Promise<RulegenContext | null> {
  let finding: RulegenContext['finding'] = null
  if (body.source === 'finding') {
    const { rows } = await db.query<Record<string, unknown>>(
      `SELECT f.tool, f.rule_id, f.category, f.severity, f.native_severity, f.title, f.message, f.path, f.start_line, f.end_line,
              f.cwe, f.vuln_ids, f.package, f.malicious, f.secret_type, f.snippet
         FROM findings f JOIN projects p ON p.id = f.project_id
        WHERE f.id = $1 AND NOT p.ai_opt_out AND p.archived_at IS NULL`,
      [body.finding_id],
    )
    if (!rows[0]) return null
    const f = findingInput(rows[0])
    finding = { tool: f.tool, rule_id: f.rule_id, category: f.category, title: f.title, message: f.message, path: f.path, cwe: f.cwe, snippet: f.snippet }
  }
  return boundRulegenContext({
    engine: body.engine,
    source: body.source,
    language: body.language ?? null,
    description: body.description ?? null,
    example: body.source === 'example' ? body.example ?? null : null,
    finding,
  })
}

export async function requestRule(db: Queryable, body: GenerateBody, userId: number, userLocale: 'fr' | 'en') {
  if (!(await connectorEnabled())) return { found: true, subject_id: null, task_id: null }
  const context = await rulegenContext(db, body)
  if (!context) return { found: false, subject_id: null, task_id: null }
  const subjectId = rulegenSubjectId(context)
  const taskId = await enqueueAiTask(db, {
    kind: 'generate-rule', subjectType: 'rule', subjectId, projectId: null,
    locale: body.locale ?? userLocale, priority: AI_PRIORITY.interactive, requestedBy: userId, context,
  })
  return { found: true, subject_id: taskId ? subjectId : null, task_id: taskId }
}

interface RuleTaskRow {
  id: string
  status: string
  output: unknown
  context: unknown
  error: string | null
  model: string | null
  model_digest: string | null
  finished_at: Date | null
}

async function latestRuleTask(db: Queryable, subjectId: string): Promise<RuleTaskRow | null> {
  const { rows } = await db.query<RuleTaskRow>(
    `SELECT id, status, output, context, error, model, model_digest, finished_at FROM ai_tasks
      WHERE kind = 'generate-rule' AND subject_type = 'rule' AND subject_id = $1 AND project_id IS NULL
      ORDER BY (status = 'done') DESC, created_at DESC LIMIT 1`,
    [subjectId],
  )
  return rows[0] ?? null
}

/** Proposition terminée et revalidée, avec son moteur ; sinon RulegenError. */
async function readyRule(db: Queryable, subjectId: string) {
  const t = await latestRuleTask(db, subjectId)
  if (!t) throw new RulegenError('not-found')
  const ctx = boundRulegenContext(t.context)
  const out = GenerateRuleOutput.safeParse(t.output)
  if (t.status !== 'done' || !ctx || !out.success) throw new RulegenError('not-ready')
  return { task: t, engine: ctx.engine, rule: out.data }
}

export async function readRule(db: Queryable, subjectId: string | undefined) {
  const enabled = await connectorEnabled()
  if (!enabled || !subjectId) return { enabled, task: null, engine: null as RuleEngine | null, available: backend !== null }
  const t = await latestRuleTask(db, subjectId)
  if (!t) return null
  const ctx = boundRulegenContext(t.context)
  const out = t.status === 'done' ? GenerateRuleOutput.safeParse(t.output) : null
  return {
    enabled: true,
    /** Test et enregistrement possibles (jeux de règles du chantier A branchés). */
    available: backend !== null,
    engine: ctx?.engine ?? null,
    task: {
      id: t.id,
      status: out && !out.success ? 'error' : t.status,
      error: out && !out.success ? 'invalid-output' : t.error,
      output: out?.success ? out.data : null,
      model: t.model,
      model_digest: t.model_digest,
      generated_at: t.finished_at?.toISOString() ?? null,
    },
  }
}

// ---- Test confiné ------------------------------------------------------------------

export interface RuleVerdict {
  passed: boolean
  positive_matches: number
  negative_matches: number
  errors: string[]
}

/** La règle trouve l'exemple positif (au moins une fois) et pas le négatif. */
export function judgeTest(r: RulesetTestResult): RuleVerdict {
  const count = (name: string) => r.samples.find(s => s.name === name)?.matches ?? -1
  const pos = count('positive')
  const neg = count('negative')
  return { passed: r.ok && pos >= 1 && neg === 0, positive_matches: pos, negative_matches: neg, errors: r.errors.slice(0, 10).map(e => String(e).slice(0, 500)) }
}

/** Test de la règle sur ses deux exemples, dans le conteneur confiné du moteur (chantier A). */
async function runTest(b: RulesetBackend, db: Queryable, engine: RuleEngine, rule: GenerateRuleOutput, userId: number): Promise<RuleVerdict> {
  return judgeTest(await b.testRuleset(db, {
    engine,
    content: rule.rule,
    samples: [
      { name: 'positive', filename: rule.positive.filename, content: rule.positive.content },
      { name: 'negative', filename: rule.negative.filename, content: rule.negative.content },
    ],
    userId,
  }))
}

export async function testRule(db: Queryable, subjectId: string, userId: number): Promise<RuleVerdict & { engine: RuleEngine }> {
  const b = requireBackend()
  const { engine, rule } = await readyRule(db, subjectId)
  return { ...(await runTest(b, db, engine, rule, userId)), engine }
}

// ---- Enregistrement confirmé par un administrateur ------------------------------

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/
export const SaveBody = z.strictObject({
  subject_id: z.string().regex(RULEGEN_SUBJECT_RE),
  ruleset_id: z.uuid().optional(),
  new_ruleset: z.strictObject({ slug: z.string().regex(SLUG_RE), name: z.string().trim().min(1).max(200) }).optional(),
  /** Modale lue et confirmée (principe 8 : l'enregistrement est confirmé). */
  confirmed: z.literal(true),
}).refine(b => !!b.ruleset_id !== !!b.new_ruleset, { message: 'ruleset_id xor new_ruleset', path: ['ruleset_id'] })
export type SaveBody = z.infer<typeof SaveBody>

export async function listRulesetsFor(db: Queryable, engine: RuleEngine): Promise<RulesetSummary[]> {
  return (await requireBackend().listRulesets(db, { engine })).filter(r => !r.archived_at)
}

/**
 * Enregistre la règle testée comme nouvelle version (origin = 'ai') d'un jeu
 * de règles existant ou nouveau. Le test est rejoué ici : une règle qui ne
 * passe plus n'est pas enregistrée.
 */
export async function saveRule(db: Queryable, body: SaveBody, userId: number) {
  const b = requireBackend()
  const who = await db.query<{ kind: string, role: string }>('SELECT kind, role FROM users WHERE id = $1', [userId])
  if (who.rows[0]?.kind !== 'human' || who.rows[0]?.role !== 'admin') throw new RulegenError('not-human')
  const { task, engine, rule } = await readyRule(db, body.subject_id)
  let target: RulesetSummary | undefined
  if (body.ruleset_id) {
    target = (await b.listRulesets(db, { engine, includeArchived: true })).find(r => r.id === body.ruleset_id)
    if (!target) throw new RulegenError('engine-mismatch')
    if (target.archived_at) throw new RulegenError('archived')
  }
  const verdict = await runTest(b, db, engine, rule, userId)
  if (!verdict.passed) throw new RulegenError('test-failed')
  const rulesetId = target?.id ?? (await b.createRuleset(db, {
    slug: body.new_ruleset!.slug, engine, name: body.new_ruleset!.name,
    description: rule.explanation.slice(0, 2000), userId,
  })).id
  const digest = task.model_digest ? ` (${task.model_digest.slice(0, 12)})` : ''
  const comment = `Proposé par IA : ${task.model ?? '?'}${digest}. ${rule.rule_id} : ${rule.explanation}`.slice(0, 2000)
  const v = await b.addRulesetVersion(db, { rulesetId, content: rule.rule, comment, origin: 'ai', userId })
  return {
    ruleset_id: rulesetId, version: v.version, sha256: v.sha256, engine, rule_id: rule.rule_id,
    model: task.model, model_digest: task.model_digest, task_id: task.id, verdict,
  }
}
