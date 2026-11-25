// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F9, simulateur de quality gate (contrat 39) : rejoue l'évaluation du gate
// (computeVerdict, la même fonction que le contrat 6, sans copie) sur les
// analyses passées, avec des règles candidates.
// - chaque analyse est rejouée avec son plan figé (G11) : mêmes résultats,
//   mêmes modules, et les exceptions telles qu'elles étaient à la fin de
//   l'analyse (approuvées avant, ni révoquées ni échues alors) ;
// - le plancher des verrous figé dans le plan (G8) s'applique aussi aux
//   règles candidates : une simulation ne peut pas montrer un assouplissement
//   que le profil interdit ;
// - deux verdicts sont recalculés : le rejeu avec les règles de l'époque et la
//   simulation avec les règles candidates. L'effet (bloquée, débloquée,
//   inchangée) compare ces deux-là, pour que seul le changement de règles
//   compte ; le verdict réel enregistré est rendu à côté, et un écart entre le
//   réel et le rejeu (tri humain changé depuis, par exemple) est compté à part ;
// - rien n'est écrit ailleurs que dans gate_simulations : ni verdict, ni
//   statut de forge, ni audit. Enregistrer les règles reste une action séparée.
// L'IA (I19) ne fait que proposer des règles candidates (origin « ai ») : la
// simulation est la même, et l'enregistrement reste humain.

import { GateRules, type VerdictDetails } from '#shared/analysis'
import type { Pool } from 'pg'
import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { applyGateFloor, planGateFloor } from '../profiles/locks'
import { computeVerdict, loadGateInput } from './evaluate'
import { byCodepoint } from '../vex/format'

/** Au plus autant d'analyses rejouées par simulation (les plus récentes d'abord). */
export const MAX_SIMULATED_SCANS = 2000
/** Au-delà, l'API rend la main et la simulation continue en tâche de fond. */
export const SYNC_SIMULATION_SCANS = 150
/** Analyses détaillées gardées dans le résultat (celles qui changent et les releases d'abord). */
export const MAX_RESULT_ITEMS = 500
export const DEFAULT_SINCE_DAYS = 90
export const MAX_SINCE_DAYS = 730

export type Verdict = VerdictDetails['verdict']
export type Effect = 'blocked' | 'unblocked' | 'unchanged'

/** Règle du gate responsable d'une raison du verdict. */
const RULE_OF_CODE: Record<string, keyof GateRules> = {
  'secret': 'max_secrets',
  'vuln': 'vuln_block_from',
  'sast': 'sast_block_from',
  'iac': 'iac_block_from',
  'kev': 'kev_blocks',
  'epss': 'epss_block_from',
  'license-denied': 'license_denied_blocks',
  'quarantine': 'quarantine_days',
  'feed-stale': 'feed_max_age_days',
}

export interface SimulationItem {
  scan_id: string
  project_id: string
  project_slug: string
  number: number
  ref: string
  trigger: string
  tag: string | null
  release: boolean
  finished_at: string
  /** Verdict enregistré. */
  actual: Verdict | null
  /** Rejeu avec les règles de l'époque. */
  replay: Verdict
  /** Rejeu avec les règles candidates. */
  simulated: Verdict
  effect: Effect
  /** Règles du gate à l'origine du changement (vide si inchangée). */
  rules: string[]
}

interface Tally { blocked: number, unblocked: number, unchanged: number }

export interface SimulationResult {
  since: string
  rules: GateRules
  /** Règles candidates différentes des règles actuelles du gate (gate_id), sinon vide. */
  changed_rules: string[]
  scans: Tally & { total: number, drift: number, errors: number }
  releases: Tally & { total: number }
  /** Pour chaque règle : analyses qu'elle bloquerait ou débloquerait. */
  by_rule: { rule: string, blocked: number, unblocked: number }[]
  /** Analyses détaillées, celles qui changent et les releases d'abord. */
  items: SimulationItem[]
  truncated: boolean
  /** Plus d'analyses que MAX_SIMULATED_SCANS dans la période : les plus anciennes ne sont pas rejouées. */
  limited: boolean
}

export interface SimulateInput {
  projectId?: string | null
  gateId?: string | null
  rules: unknown
  since: Date
  origin?: 'manual' | 'ai'
  createdBy?: number | null
  /** Ligne gate_simulations déjà créée (tâche de fond). */
  simulationId?: string
}

/** Corps de POST /api/gates/simulations (repris par l'OpenAPI). */
export const simulationRequestSchema = z.strictObject({
  gate_id: z.string().uuid().optional(),
  project_id: z.string().uuid().optional(),
  rules: z.record(z.string(), z.unknown()),
  since_days: z.number().int().min(1).max(MAX_SINCE_DAYS).default(DEFAULT_SINCE_DAYS),
}).refine(b => !!b.gate_id || !!b.project_id, { message: 'gate_id or project_id', path: ['gate_id'] })

/** Simulations en tâche de fond simultanées, au plus (le pool PostgreSQL reste libre pour le reste). */
export const MAX_BACKGROUND_SIMULATIONS = 2

export class SimulationError extends Error {
  constructor(public code: 'E_VALIDATION' | 'E_NOT_FOUND' | 'E_RATE_LIMITED') {
    super(code)
  }
}

const isBlocking = (v: Verdict | null) => v !== null && v !== 'passed'

function blockingCodes(d: VerdictDetails): Set<string> {
  return new Set(d.reasons.filter(r => r.blocking).map(r => r.code))
}

/** Règles responsables : raisons bloquantes apparues (bloquée) ou disparues (débloquée), et new_code_only s'il a changé. */
export function responsibleRules(replay: VerdictDetails, simulated: VerdictDetails): string[] {
  const before = blockingCodes(replay)
  const after = blockingCodes(simulated)
  const out = new Set<string>()
  for (const c of after) if (!before.has(c) && RULE_OF_CODE[c]) out.add(RULE_OF_CODE[c])
  for (const c of before) if (!after.has(c) && RULE_OF_CODE[c]) out.add(RULE_OF_CODE[c])
  if (replay.rules.new_code_only !== simulated.rules.new_code_only) out.add('new_code_only')
  return [...out].sort(byCodepoint)
}

export function effectOf(replay: Verdict, simulated: Verdict): Effect {
  if (!isBlocking(replay) && isBlocking(simulated)) return 'blocked'
  if (isBlocking(replay) && !isBlocking(simulated)) return 'unblocked'
  return 'unchanged'
}

export function changedRules(current: GateRules | null, candidate: GateRules): string[] {
  if (!current) return []
  return (Object.keys(candidate) as (keyof GateRules)[]).filter(k => current[k] !== candidate[k]).sort(byCodepoint)
}

interface ScanRow {
  id: string
  project_id: string
  project_slug: string
  number: number
  ref: string
  trigger: string
  tag: string | null
  verdict: Verdict | null
  finished_at: Date
}

async function scansToReplay(db: Queryable, p: { projectId: string | null, gateId: string | null, since: Date }): Promise<ScanRow[]> {
  const r = await db.query<ScanRow>(
    `SELECT s.id, s.project_id, p.slug AS project_slug, s.number, s.ref, s.trigger, rc.tag, s.verdict, s.finished_at
       FROM scans s JOIN projects p ON p.id = s.project_id
       LEFT JOIN LATERAL (SELECT tag FROM release_candidates c WHERE c.scan_id = s.id ORDER BY seen_at LIMIT 1) rc ON true
      WHERE s.status = 'done' AND s.verdict IS NOT NULL AND s.finished_at >= $3
        AND ($1::uuid IS NULL OR s.project_id = $1) AND ($2::uuid IS NULL OR s.gate_id = $2)
      ORDER BY s.finished_at DESC, s.id
      LIMIT ${MAX_SIMULATED_SCANS + 1}`,
    [p.projectId, p.gateId, p.since.toISOString()],
  )
  return r.rows
}

/** Calcul de la simulation, en lecture seule. */
export async function computeSimulation(db: Queryable, p: { projectId: string | null, gateId: string | null, rules: GateRules, since: Date }): Promise<SimulationResult> {
  const rows = await scansToReplay(db, p)
  const limited = rows.length > MAX_SIMULATED_SCANS
  const scans = rows.slice(0, MAX_SIMULATED_SCANS)
  let current: GateRules | null = null
  if (p.gateId) {
    const g = await db.query<{ rules: unknown }>('SELECT rules FROM gates WHERE id = $1', [p.gateId])
    const parsed = GateRules.safeParse(g.rows[0]?.rules)
    current = parsed.success ? parsed.data : null
  }
  const result: SimulationResult = {
    since: p.since.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    rules: p.rules,
    changed_rules: changedRules(current, p.rules),
    scans: { total: 0, blocked: 0, unblocked: 0, unchanged: 0, drift: 0, errors: 0 },
    releases: { total: 0, blocked: 0, unblocked: 0, unchanged: 0 },
    by_rule: [],
    items: [],
    truncated: false,
    limited,
  }
  const byRule = new Map<string, { blocked: number, unblocked: number }>()
  const items: SimulationItem[] = []
  for (const s of scans) {
    let replay: VerdictDetails
    let simulated: VerdictDetails
    try {
      const { input, plan } = await loadGateInput(db, s.id, s.finished_at, { exceptionsAt: s.finished_at })
      replay = computeVerdict(input)
      simulated = computeVerdict({ ...input, rules: applyGateFloor(p.rules, planGateFloor(plan)) })
    }
    catch {
      // Une analyse illisible (plan corrompu) n'arrête pas la simulation : elle est comptée à part.
      result.scans.errors++
      continue
    }
    const effect = effectOf(replay.verdict, simulated.verdict)
    const rules = effect === 'unchanged' ? [] : responsibleRules(replay, simulated)
    const release = s.trigger === 'release' || s.tag !== null
    result.scans.total++
    result.scans[effect]++
    if (s.verdict !== replay.verdict) result.scans.drift++
    if (release) {
      result.releases.total++
      result.releases[effect]++
    }
    if (effect !== 'unchanged') {
      for (const r of rules) {
        const t = byRule.get(r) ?? { blocked: 0, unblocked: 0 }
        t[effect]++
        byRule.set(r, t)
      }
    }
    items.push({
      scan_id: s.id, project_id: s.project_id, project_slug: s.project_slug, number: s.number, ref: s.ref, trigger: s.trigger,
      tag: s.tag, release, finished_at: s.finished_at.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      actual: s.verdict, replay: replay.verdict, simulated: simulated.verdict, effect, rules,
    })
  }
  result.by_rule = [...byRule.entries()].map(([rule, t]) => ({ rule, ...t })).sort((a, b) => a.rule.localeCompare(b.rule))
  // Ordre de lecture : ce qui change d'abord, puis les releases, puis le reste (le plus récent d'abord).
  const rank = (i: SimulationItem) => (i.effect !== 'unchanged' ? 0 : i.release ? 1 : 2)
  const sorted = items.map((it, idx) => ({ it, idx })).sort((a, b) => rank(a.it) - rank(b.it) || a.idx - b.idx).map(x => x.it)
  result.truncated = sorted.length > MAX_RESULT_ITEMS
  result.items = sorted.slice(0, MAX_RESULT_ITEMS)
  return result
}

function parseRules(rules: unknown): GateRules {
  const parsed = GateRules.safeParse(rules)
  if (!parsed.success) throw new SimulationError('E_VALIDATION')
  return parsed.data
}

async function checkScope(db: Queryable, projectId: string | null, gateId: string | null): Promise<void> {
  if (!projectId && !gateId) throw new SimulationError('E_VALIDATION')
  if (projectId && !(await db.query('SELECT 1 FROM projects WHERE id = $1', [projectId])).rowCount) throw new SimulationError('E_NOT_FOUND')
  if (gateId && !(await db.query('SELECT 1 FROM gates WHERE id = $1', [gateId])).rowCount) throw new SimulationError('E_NOT_FOUND')
}

async function insertPending(db: Queryable, p: { projectId: string | null, gateId: string | null, rules: GateRules, since: Date, origin: 'manual' | 'ai', createdBy: number | null }): Promise<string> {
  const r = await db.query<{ id: string }>(
    `INSERT INTO gate_simulations (project_id, gate_id, rules, since, origin, status, created_by)
     VALUES ($1, $2, $3, $4, $5, 'pending', $6) RETURNING id`,
    [p.projectId, p.gateId, JSON.stringify(p.rules), p.since.toISOString(), p.origin, p.createdBy],
  )
  return r.rows[0]!.id
}

/**
 * Contrat 39 : rejoue l'évaluation avec les règles candidates sur les analyses
 * terminées depuis `since` (d'un projet, d'un gate, ou des deux). N'écrit que
 * dans gate_simulations (une ligne, « done » avec son résultat, ou « error »).
 */
export async function simulateGate(db: Queryable, input: SimulateInput): Promise<{ id: string, result: SimulationResult }> {
  const rules = parseRules(input.rules)
  const projectId = input.projectId ?? null
  const gateId = input.gateId ?? null
  if (!(input.since instanceof Date) || !Number.isFinite(input.since.getTime())) throw new SimulationError('E_VALIDATION')
  await checkScope(db, projectId, gateId)
  const id = input.simulationId ?? await insertPending(db, { projectId, gateId, rules, since: input.since, origin: input.origin ?? 'manual', createdBy: input.createdBy ?? null })
  try {
    const result = await computeSimulation(db, { projectId, gateId, rules, since: input.since })
    await db.query(`UPDATE gate_simulations SET status = 'done', result = $2 WHERE id = $1`, [id, JSON.stringify(result)])
    return { id, result }
  }
  catch (err) {
    await db.query(`UPDATE gate_simulations SET status = 'error' WHERE id = $1 AND status = 'pending'`, [id])
    throw err
  }
}

export interface SimulationRow {
  id: string
  project_id: string | null
  gate_id: string | null
  rules: GateRules
  since: string
  origin: 'manual' | 'ai'
  status: 'pending' | 'done' | 'error'
  result: SimulationResult | null
  created_by: string | null
  created_at: string
}

const TS = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

export async function getSimulation(db: Queryable, id: string): Promise<SimulationRow | null> {
  const r = await db.query<SimulationRow>(
    `SELECT s.id, s.project_id, s.gate_id, s.rules, ${TS('s.since')} AS since, s.origin, s.status, s.result,
            u.username AS created_by, ${TS('s.created_at')} AS created_at
       FROM gate_simulations s LEFT JOIN users u ON u.id = s.created_by WHERE s.id = $1`, [id])
  return r.rows[0] ?? null
}

/** Nombre d'analyses à rejouer (choix entre réponse immédiate et tâche de fond). */
async function countScans(db: Queryable, projectId: string | null, gateId: string | null, since: Date): Promise<number> {
  const r = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM scans
      WHERE status = 'done' AND verdict IS NOT NULL AND finished_at >= $3
        AND ($1::uuid IS NULL OR project_id = $1) AND ($2::uuid IS NULL OR gate_id = $2)`,
    [projectId, gateId, since.toISOString()])
  return r.rows[0]?.n ?? 0
}

/** Simulations lancées en tâche de fond par ce processus (tests : attendre leur fin). */
const background = new Set<Promise<unknown>>()
export function pendingSimulations(): Promise<unknown[]> {
  return Promise.all([...background])
}

/**
 * Point d'entrée de l'API : un historique court est simulé tout de suite ; un
 * historique long rend la ligne « pending » et continue en tâche de fond (la
 * page interroge GET /api/gates/simulations/:id jusqu'au résultat).
 */
export async function startSimulation(pool: Pool | Queryable, input: Omit<SimulateInput, 'simulationId'>): Promise<SimulationRow> {
  const rules = parseRules(input.rules)
  const projectId = input.projectId ?? null
  const gateId = input.gateId ?? null
  await checkScope(pool, projectId, gateId)
  const n = await countScans(pool, projectId, gateId, input.since)
  if (n <= SYNC_SIMULATION_SCANS) {
    const { id } = await simulateGate(pool, { ...input, rules })
    return (await getSimulation(pool, id))!
  }
  if (background.size >= MAX_BACKGROUND_SIMULATIONS) throw new SimulationError('E_RATE_LIMITED')
  const id = await insertPending(pool, { projectId, gateId, rules, since: input.since, origin: input.origin ?? 'manual', createdBy: input.createdBy ?? null })
  const job = simulateGate(pool, { ...input, rules, simulationId: id })
    .catch(err => console.error('[gates] simulation failed:', (err as Error).message))
    .finally(() => background.delete(job))
  background.add(job)
  return (await getSimulation(pool, id))!
}

export function sinceFromDays(days: number, now = new Date()): Date {
  return new Date(now.getTime() - days * 86_400_000)
}
