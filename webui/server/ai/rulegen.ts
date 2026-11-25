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
// demande helper validate-ruleset) appartiennent au chantier A
// (webui/server/rulesets/store.ts et engine.ts) : ils sont appelés par leur
// contrat, branché par défaut et remplaçable par setRulesetBackend (tests).
// Le test est asynchrone : la demande validate-ruleset est déposée au helper
// root (administrateur), la page la suit, puis le verdict est calculé ici à
// partir du résultat de cette demande, après avoir vérifié qu'elle porte
// exactement la règle et les exemples de la proposition. L'enregistrement
// exige une telle demande terminée et réussie.

import { createHash } from 'node:crypto'
import type { H3Event } from 'h3'
import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { getHelperRequest } from '../utils/requests'
import { addRulesetVersion, createRuleset, listRulesets, type RulesetEngine } from '../rulesets/store'
import { submitRulesetTest } from '../rulesets/engine'
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

export interface RulesetTestRequest {
  type: string
  status: 'pending' | 'running' | 'ok' | 'error' | 'rejected' | 'lost'
  code: string | null
  params: Record<string, unknown>
  output: Record<string, unknown> | null
}

export interface RulesetBackend {
  createRuleset: (db: Queryable, a: { slug: string, engine: string, name: string, description?: string, userId: number }) => Promise<{ id: string }>
  addRulesetVersion: (db: Queryable, a: { rulesetId: string, content: string, comment?: string, origin: 'manual' | 'import' | 'ai', userId: number }) => Promise<{ version: number, sha256: string }>
  listRulesets: (db: Queryable, a: { engine?: string, includeArchived?: boolean }) => Promise<RulesetSummary[]>
  /** Dépose la demande validate-ruleset (202) ; la page la suit par /api/requests/:id. */
  submitTest: (event: H3Event, a: { engine: string, content: string, samples: { name: string, content: string }[] }) => Promise<{ request_id: string }>
  readTest: (db: Queryable, requestId: string) => Promise<RulesetTestRequest | null>
}

/** Jeux de règles du chantier A (G4). */
export const rulesetStore: RulesetBackend = {
  createRuleset: (db, a) => createRuleset(db, { ...a, engine: a.engine as RulesetEngine }),
  addRulesetVersion: (db, a) => addRulesetVersion(db, a),
  listRulesets: (db, a) => listRulesets(db, { ...a, engine: a.engine as RulesetEngine | undefined }),
  submitTest: (event, a) => submitRulesetTest(event, { engine: a.engine as RulesetEngine, content: a.content, samples: a.samples }),
  readTest: (db, id) => getHelperRequest(db, id),
}

let backend: RulesetBackend | null = rulesetStore

/** Remplace les jeux de règles du chantier A (double en test) ; null les retire. */
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
export function judgeTest(r: RulesetTestResult, names = { positive: 'positive', negative: 'negative' }): RuleVerdict {
  const count = (name: string) => r.samples.find(s => s.name === name)?.matches ?? -1
  const pos = count(names.positive)
  const neg = count(names.negative)
  return { passed: r.ok && pos >= 1 && neg === 0, positive_matches: pos, negative_matches: neg, errors: r.errors.slice(0, 10).map(e => String(e).slice(0, 500)) }
}

const EXT_RE = /\.[A-Za-z0-9]{1,10}$/
/** Exemples déposés au moteur : le nom porte l'extension du fichier proposé (le moteur choisit le langage par elle). */
export function testSamples(rule: GenerateRuleOutput) {
  const ext = (f: string) => EXT_RE.exec(f.split('/').pop() ?? '')?.[0] ?? '.txt'
  const positive = `positive${ext(rule.positive.filename)}`
  const negative = `negative${ext(rule.negative.filename)}`
  return {
    names: { positive, negative },
    samples: [{ name: positive, content: rule.positive.content }, { name: negative, content: rule.negative.content }],
  }
}

const sha256Hex = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex')
/** Exemples comparés par nom et empreinte du contenu, indépendamment de l'ordre des clés (jsonb). */
const sampleKey = (l: unknown) => (Array.isArray(l) ? l : [])
  .map(x => `${String((x as { name?: unknown })?.name)}:${sha256Hex(String((x as { content?: unknown })?.content))}`).join('|')

/** Dépose le test confiné de la règle proposée (administrateur) ; rend l'identifiant de demande. */
export async function testRule(event: H3Event, db: Queryable, subjectId: string) {
  const b = requireBackend()
  const { engine, rule } = await readyRule(db, subjectId)
  return b.submitTest(event, { engine, content: rule.rule, samples: testSamples(rule).samples })
}

/**
 * Verdict d'une demande de test : elle doit être une validate-ruleset qui
 * porte exactement la règle et les exemples de la proposition (jamais une
 * autre règle validée ailleurs). En cours : null.
 */
async function verdictOf(b: RulesetBackend, db: Queryable, engine: RuleEngine, rule: GenerateRuleOutput, requestId: string): Promise<RuleVerdict | null> {
  const r = UUID_RE.test(requestId) ? await b.readTest(db, requestId) : null
  const { names, samples } = testSamples(rule)
  const p = r?.params ?? {}
  const same = r?.type === 'validate-ruleset' && p.engine === engine && p.sha256 === sha256Hex(rule.rule)
    && sampleKey(p.samples) === sampleKey(samples)
  if (!r || !same) throw new RulegenError('not-found')
  if (r.status === 'pending' || r.status === 'running') return null
  if (r.status !== 'ok' || !r.output) return { passed: false, positive_matches: -1, negative_matches: -1, errors: [String(r.code ?? r.status).slice(0, 100)] }
  const out = r.output as Partial<RulesetTestResult>
  return judgeTest({
    ok: out.ok === true,
    errors: Array.isArray(out.errors) ? out.errors.map(String) : [],
    samples: Array.isArray(out.samples) ? out.samples.filter(x => x && typeof x.name === 'string' && typeof x.matches === 'number') : [],
  }, names)
}

export async function ruleVerdict(db: Queryable, subjectId: string, requestId: string): Promise<(RuleVerdict & { engine: RuleEngine, done: true }) | { engine: RuleEngine, done: false }> {
  const b = requireBackend()
  const { engine, rule } = await readyRule(db, subjectId)
  const v = await verdictOf(b, db, engine, rule, requestId)
  return v ? { ...v, engine, done: true } : { engine, done: false }
}

// ---- Enregistrement confirmé par un administrateur ------------------------------

const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/
export const VerdictQuery = z.strictObject({ subject_id: z.string().regex(RULEGEN_SUBJECT_RE), request_id: z.string().regex(UUID_RE) })

export const SaveBody = z.strictObject({
  subject_id: z.string().regex(RULEGEN_SUBJECT_RE),
  /** Demande validate-ruleset terminée de cette règle et de ces exemples. */
  test_request_id: z.string().regex(UUID_RE),
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
 * de règles existant ou nouveau, seulement si la demande de test indiquée
 * porte exactement cette règle et ces exemples, et qu'elle a réussi.
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
  const verdict = await verdictOf(b, db, engine, rule, body.test_request_id)
  if (!verdict) throw new RulegenError('not-ready')
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
