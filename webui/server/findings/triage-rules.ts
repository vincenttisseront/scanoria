// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Règles de tri en masse (F4) : une règle porte sur un chemin (glob), un
// outil, une règle d'outil et des gravités, et pose un statut
// (false-positive, accepted ou confirmed) avec une justification et une date
// de fin obligatoires.
// - Effet simulé avant l'application : résultats touchés par projet et liste.
// - Appliquée à la création de la règle et à chaque ingestion, aux seuls
//   résultats « nouveaux » : une décision humaine (confirmé, faux positif,
//   accepté) n'est jamais écrasée. findings.triage_rule_id est rempli.
// - Une règle « accepted » vaut, pour le gate, une exception approuvée :
//   seul un administrateur la crée, et elle suit les mêmes interdits (jamais
//   un résultat malveillant H4, jamais un secret sous verrou G8).
// - Échue ou révoquée, la règle cesse de s'appliquer et les résultats qu'elle
//   avait triés, s'ils n'ont pas été retouchés depuis, redeviennent « nouveaux ».
// - Audit : une ligne par résultat jusqu'à AUDIT_DETAIL_MAX, au-delà une ligne
//   de synthèse avec le nombre et les premiers identifiants (le journal reste
//   lisible et sa taille bornée, la liste complète se relit par triage_rule_id).

import { z } from 'zod'
import { SEVERITIES, type Severity } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { globToRegExp } from '../gates/evaluate'
import { isoDay, isValidDay, MAX_EXCEPTION_DAYS } from './exceptions'
import { projectLocks, secretsLocked } from './locks'
import { redact } from './redact'

export const TRIAGE_ACTIONS = ['false-positive', 'accepted', 'confirmed'] as const
export type TriageAction = (typeof TRIAGE_ACTIONS)[number]

/** Au plus 8 jokers dans un glob : borne le retour arrière (comme les exceptions « path »). */
const GLOB_RE = /^[^\0\n]{1,512}$/
export const ruleMatchSchema = z.strictObject({
  path: z.string().trim().regex(GLOB_RE).refine(g => (g.match(/[*?]/g) ?? []).length <= 8, 'too_many_wildcards').optional(),
  tool: z.string().regex(MODULE_ID_RE).optional(),
  rule: z.string().trim().min(1).max(255).optional(),
  severity: z.array(z.enum(SEVERITIES)).min(1).max(SEVERITIES.length).optional(),
}).refine(m => !!(m.path || m.tool || m.rule || m.severity?.length), 'empty_match')
export type RuleMatch = z.infer<typeof ruleMatchSchema>

export const triageRuleSchema = z.strictObject({
  /** null : règle de toute l'appliance (administrateur seulement). */
  project_id: z.string().uuid().nullable(),
  match: ruleMatchSchema,
  action: z.enum(TRIAGE_ACTIONS),
  reason: z.string().trim().min(3).max(2000),
  expires_on: z.string().refine(isValidDay),
})
export type TriageRuleInput = z.infer<typeof triageRuleSchema>

export class TriageRuleError extends Error {
  constructor(public code: 'E_NOT_FOUND' | 'E_VALIDATION' | 'E_FORBIDDEN', public detail: string | null = null) {
    super(code)
  }
}

/** Seuil au-delà duquel l'audit passe d'une ligne par résultat à une synthèse. */
export const AUDIT_DETAIL_MAX = 200
/** Résultats candidats lus au plus par simulation ou application. */
const MAX_CANDIDATES = 50_000
/** Résultats listés au plus dans une simulation. */
const SIMULATION_LIST = 200

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '')
}

/** Correspondance d'un résultat (forme lue en base) avec le filtre d'une règle. */
export function compileMatch(match: RuleMatch): (f: { path: string | null, tool: string, rule_id: string, severity: string }) => boolean {
  const re = match.path ? globToRegExp(normalizePath(match.path)) : null
  const severities = match.severity?.length ? new Set<string>(match.severity) : null
  return f => (!match.tool || f.tool === match.tool)
    && (!match.rule || f.rule_id === match.rule)
    && (!severities || severities.has(f.severity))
    && (!re || (!!f.path && re.test(normalizePath(f.path))))
}

interface Candidate {
  id: string
  project_id: string
  project_slug: string
  tool: string
  rule_id: string
  severity: Severity
  path: string | null
  title: string
  secret_type: string | null
}

/**
 * Résultats « nouveaux » que la règle toucherait : jamais un malveillant (H4),
 * jamais un secret d'un projet dont les secrets sont verrouillés (G8) pour une
 * règle « accepted ». ids : limité à ces résultats (ingestion).
 */
async function candidates(db: Queryable, rule: { project_id: string | null, match: RuleMatch, action: TriageAction }, ids?: string[]): Promise<Candidate[]> {
  const params: unknown[] = [rule.project_id, rule.match.tool ?? null, rule.match.rule ?? null, rule.match.severity ?? null]
  let restrict = ''
  if (ids) {
    params.push(ids)
    restrict = `AND f.id = ANY($${params.length}::uuid[])`
  }
  const { rows } = await db.query<Candidate>(
    `SELECT f.id, f.project_id, p.slug AS project_slug, f.tool, f.rule_id, f.severity, f.path, f.title, f.secret_type
       FROM findings f JOIN projects p ON p.id = f.project_id
      WHERE ($1::uuid IS NULL OR f.project_id = $1) AND p.archived_at IS NULL
        AND (f.status = 'new' OR (f.status = 'accepted' AND f.status_until < current_date))
        AND NOT f.malicious
        AND ($2::text IS NULL OR f.tool = $2) AND ($3::text IS NULL OR f.rule_id = $3)
        AND ($4::text[] IS NULL OR f.severity = ANY($4::text[]))
        ${restrict}
      ORDER BY f.project_id, f.id LIMIT ${MAX_CANDIDATES}`,
    params,
  )
  const test = compileMatch(rule.match)
  let out = rows.filter(test)
  if (rule.action === 'accepted') {
    const locked = new Map<string, boolean>()
    for (const pid of new Set(out.filter(f => f.secret_type).map(f => f.project_id))) {
      locked.set(pid, secretsLocked(await projectLocks(db, pid)))
    }
    out = out.filter(f => !(f.secret_type && locked.get(f.project_id)))
  }
  return out
}

export interface Simulation {
  total: number
  projects: { project_id: string, project_slug: string, count: number }[]
  items: Omit<Candidate, 'secret_type'>[]
  truncated: boolean
}

function validate(input: TriageRuleInput, today: string): void {
  const max = isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))
  if (input.expires_on < today || input.expires_on > max) throw new TriageRuleError('E_VALIDATION', 'expires_on')
}

/** Effet d'une règle avant son enregistrement (rien n'est écrit). */
export async function simulateTriageRule(db: Queryable, input: TriageRuleInput, today = isoDay()): Promise<Simulation> {
  validate(input, today)
  const list = await candidates(db, input)
  const by = new Map<string, { project_id: string, project_slug: string, count: number }>()
  for (const f of list) {
    const p = by.get(f.project_id) ?? { project_id: f.project_id, project_slug: f.project_slug, count: 0 }
    p.count++
    by.set(f.project_id, p)
  }
  return {
    total: list.length,
    projects: [...by.values()].sort((a, b) => b.count - a.count || a.project_slug.localeCompare(b.project_slug)),
    items: list.slice(0, SIMULATION_LIST).map(({ secret_type: _s, ...f }) => f),
    truncated: list.length > SIMULATION_LIST || list.length >= MAX_CANDIDATES,
  }
}

export interface TriageRuleRow {
  id: string
  project_id: string | null
  project_slug: string | null
  match: RuleMatch
  action: TriageAction
  reason: string
  expires_on: string
  applied_count: number
  created_by: string | null
  created_at: string
  revoked_at: string | null
  revoked_by: string | null
  active: boolean
}

const TS = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`
const COLUMNS = `r.id, r.project_id, p.slug AS project_slug, r.match, r.action, r.reason, to_char(r.expires_on, 'YYYY-MM-DD') AS expires_on,
  r.applied_count, uc.username AS created_by, ${TS('r.created_at')} AS created_at, ${TS('r.revoked_at')} AS revoked_at,
  ur.username AS revoked_by, (r.revoked_at IS NULL AND r.expires_on >= current_date) AS active`
const FROM = `FROM triage_rules r LEFT JOIN projects p ON p.id = r.project_id
  LEFT JOIN users uc ON uc.id = r.created_by LEFT JOIN users ur ON ur.id = r.revoked_by`

export async function listTriageRules(db: Queryable, opts: { projectId?: string, all?: boolean }): Promise<TriageRuleRow[]> {
  const r = await db.query<TriageRuleRow>(
    `SELECT ${COLUMNS} ${FROM}
      WHERE ($1::uuid IS NULL OR r.project_id = $1 OR r.project_id IS NULL)
        ${opts.all ? '' : 'AND r.revoked_at IS NULL AND r.expires_on >= current_date'}
      ORDER BY r.created_at DESC LIMIT 500`,
    [opts.projectId ?? null],
  )
  return r.rows
}

export async function getTriageRule(db: Queryable, id: string): Promise<TriageRuleRow | null> {
  const r = await db.query<TriageRuleRow>(`SELECT ${COLUMNS} ${FROM} WHERE r.id = $1`, [id])
  return r.rows[0] ?? null
}

/** Statut posé et audit, en lot ; renvoie les résultats touchés. */
async function applyTo(db: Queryable, rule: { id: string, action: TriageAction, reason: string, expires_on: string, created_by: number | null },
  list: Candidate[], actor: AuditActor, via: 'create' | 'ingest'): Promise<number> {
  if (!list.length) return 0
  const ids = list.map(f => f.id)
  const accepted = rule.action === 'accepted'
  const res = await db.query<{ id: string }>(
    `UPDATE findings SET status = $2, status_reason = $3, status_until = $4::date, status_by = $5, status_at = now(),
            triage_rule_id = $6, updated_at = now()
      WHERE id = ANY($1::uuid[])
        AND (status = 'new' OR (status = 'accepted' AND status_until < current_date)) AND NOT malicious
      RETURNING id`,
    [ids, rule.action, rule.reason, accepted ? rule.expires_on : null, rule.created_by, rule.id],
  )
  const touched = res.rows.map(r => r.id)
  if (!touched.length) return 0
  await db.query('UPDATE triage_rules SET applied_count = applied_count + $2 WHERE id = $1', [rule.id, touched.length])
  if (touched.length <= AUDIT_DETAIL_MAX) {
    for (const id of touched) {
      await writeAudit(db, {
        actor, action: 'finding.triage-rule', outcome: 'success', targetType: 'finding', targetId: id,
        details: { rule_id: rule.id, status: rule.action, via },
      })
    }
  }
  else {
    await writeAudit(db, {
      actor, action: 'triage-rule.apply', outcome: 'success', targetType: 'triage-rule', targetId: rule.id,
      details: { status: rule.action, via, count: touched.length, first_findings: touched.slice(0, AUDIT_DETAIL_MAX), summarized: true },
    })
  }
  return touched.length
}

/**
 * Enregistre une règle et l'applique aussitôt. Droits : « accepted » et toute
 * règle de toute l'appliance (project_id null) exigent le rôle admin.
 */
export async function createTriageRule(db: Queryable, input: TriageRuleInput, user: { id: number, username: string, role: string, ip?: string | null }, today = isoDay()): Promise<{ rule: TriageRuleRow, applied: number }> {
  validate(input, today)
  if ((input.action === 'accepted' || input.project_id === null) && user.role !== 'admin') throw new TriageRuleError('E_FORBIDDEN')
  if (input.project_id) {
    const p = await db.query('SELECT 1 FROM projects WHERE id = $1', [input.project_id])
    if (!p.rowCount) throw new TriageRuleError('E_NOT_FOUND')
  }
  const reason = redact(input.reason.trim())
  const r = await db.query<{ id: string }>(
    `INSERT INTO triage_rules (project_id, match, action, reason, expires_on, created_by)
     VALUES ($1, $2, $3, $4, $5::date, $6) RETURNING id`,
    [input.project_id, JSON.stringify(input.match), input.action, reason, input.expires_on, user.id],
  )
  const id = r.rows[0]!.id
  const actor: AuditActor = { type: 'user', userId: user.id, username: user.username, ip: user.ip ?? null }
  await writeAudit(db, {
    actor, action: 'triage-rule.create', outcome: 'success', targetType: 'triage-rule', targetId: id,
    details: { project_id: input.project_id, match: input.match, action: input.action, reason, expires_on: input.expires_on },
  })
  const applied = await applyTo(db, { id, action: input.action, reason, expires_on: input.expires_on, created_by: user.id },
    await candidates(db, input), actor, 'create')
  return { rule: (await getTriageRule(db, id))!, applied }
}

/** Résultats encore triés par la règle (statut inchangé depuis) remis à « nouveau ». */
async function undo(db: Queryable, ruleId: string, action: string): Promise<number> {
  const r = await db.query(
    `UPDATE findings SET status = 'new', status_reason = NULL, status_until = NULL, status_by = NULL, status_at = now(),
            triage_rule_id = NULL, updated_at = now()
      WHERE triage_rule_id = $1 AND status = $2`,
    [ruleId, action],
  )
  return r.rowCount ?? 0
}

/** Révoque une règle ; ses effets encore en place sont annulés. Droits comme à la création. */
export async function revokeTriageRule(db: Queryable, id: string, user: { id: number, username: string, role: string, ip?: string | null }): Promise<{ rule: TriageRuleRow, reverted: number }> {
  const cur = await db.query<{ action: string, project_id: string | null, revoked: boolean }>(
    'SELECT action, project_id, revoked_at IS NOT NULL AS revoked FROM triage_rules WHERE id = $1 FOR UPDATE', [id])
  const rule = cur.rows[0]
  if (!rule) throw new TriageRuleError('E_NOT_FOUND')
  if ((rule.action === 'accepted' || rule.project_id === null) && user.role !== 'admin') throw new TriageRuleError('E_FORBIDDEN')
  let reverted = 0
  if (!rule.revoked) {
    await db.query('UPDATE triage_rules SET revoked_at = now(), revoked_by = $2 WHERE id = $1', [id, user.id])
    reverted = await undo(db, id, rule.action)
    await writeAudit(db, {
      actor: { type: 'user', userId: user.id, username: user.username, ip: user.ip ?? null },
      action: 'triage-rule.revoke', outcome: 'success', targetType: 'triage-rule', targetId: id,
      details: { project_id: rule.project_id, reverted },
    })
  }
  return { rule: (await getTriageRule(db, id))!, reverted }
}

/**
 * Ingestion (contrat 5) : règles actives du projet et de l'appliance
 * appliquées aux résultats qui viennent d'être enregistrés, la plus ancienne
 * d'abord. Renvoie le nombre de résultats triés.
 */
export async function applyTriageRulesOnIngest(db: Queryable, projectId: string, findingIds: string[]): Promise<number> {
  if (!findingIds.length) return 0
  const { rows } = await db.query<{ id: string, project_id: string | null, match: unknown, action: TriageAction, reason: string, expires_on: string, created_by: number | null }>(
    `SELECT id, project_id, match, action, reason, to_char(expires_on, 'YYYY-MM-DD') AS expires_on, created_by::int AS created_by
       FROM triage_rules
      WHERE (project_id = $1 OR project_id IS NULL) AND revoked_at IS NULL AND expires_on >= current_date
      ORDER BY created_at, id LIMIT 500`,
    [projectId],
  )
  let remaining = [...findingIds]
  let total = 0
  for (const r of rows) {
    if (!remaining.length) break
    const match = ruleMatchSchema.safeParse(r.match)
    if (!match.success) continue
    const list = await candidates(db, { project_id: projectId, match: match.data, action: r.action }, remaining)
    const n = await applyTo(db, r, list, { type: 'system', username: 'triage-rule' }, 'ingest')
    if (n) {
      const done = new Set(list.map(f => f.id))
      remaining = remaining.filter(id => !done.has(id))
      total += n
    }
  }
  return total
}

/** Tâche périodique : effets des règles échues annulés (une fois). */
export async function expireTriageRules(db: Queryable): Promise<number> {
  const { rows } = await db.query<{ id: string, action: string }>(
    `SELECT DISTINCT r.id, r.action FROM triage_rules r JOIN findings f ON f.triage_rule_id = r.id AND f.status = r.action
      WHERE r.expires_on < current_date LIMIT 200`,
  )
  let n = 0
  for (const r of rows) {
    const reverted = await undo(db, r.id, r.action)
    if (reverted) {
      n += reverted
      await writeAudit(db, {
        actor: { type: 'system' }, action: 'triage-rule.expire', outcome: 'success', targetType: 'triage-rule', targetId: r.id,
        details: { reverted },
      })
    }
  }
  return n
}

// ---------------------------------------------------------------- propositions (I3, I7)

export interface RuleProposal {
  source: 'triage-finding'
  project_id: string
  match: RuleMatch
  action: 'false-positive'
  reason_kind: string
  count: number
  finding_ids: string[]
  /** Justification proposée, reprise des explications de l'IA (à relire). */
  reason: string
}

/** Au moins autant de résultats pour qu'une raison commune devienne une proposition de règle. */
export const PROPOSAL_MIN = 3

/** Plus long préfixe de dossier commun, en glob (« tests/** ») ; null si aucun. */
export function commonDirGlob(paths: (string | null)[]): string | null {
  const parts = paths.map(p => (p ? normalizePath(p).split('/').slice(0, -1) : null))
  if (parts.some(p => !p || !p.length)) return null
  const first = parts[0]!
  let n = 0
  while (n < first.length && parts.every(p => p![n] === first[n])) n++
  if (!n) return null
  const glob = `${first.slice(0, n).join('/')}/**`
  return /[*?[\]]/.test(first.slice(0, n).join('/')) ? null : glob
}

/**
 * I3 → F4 : quand plusieurs résultats nouveaux d'un projet, de même outil et
 * de même règle, sont jugés « faux positif probable » par le pré-tri pour la
 * même raison citée (code de test, valeur factice…), une règle F4 pré-remplie
 * est PROPOSÉE. Rien n'est enregistré : l'enregistrement reste un clic humain.
 * Rien pour un projet « aucun envoi à l'IA ».
 */
export async function proposeTriageRules(db: Queryable, projectId: string): Promise<RuleProposal[]> {
  const { rows } = await db.query<{ id: string, tool: string, rule_id: string, path: string | null, output: unknown }>(
    `SELECT DISTINCT ON (f.id) f.id, f.tool, f.rule_id, f.path, t.output
       FROM findings f JOIN projects p ON p.id = f.project_id
       JOIN ai_tasks t ON t.kind = 'triage-finding' AND t.status = 'done' AND t.subject_type = 'finding' AND t.subject_id = f.id::text
      WHERE f.project_id = $1 AND NOT p.ai_opt_out AND f.status = 'new' AND NOT f.malicious
      ORDER BY f.id, t.finished_at DESC NULLS LAST
      LIMIT 5000`,
    [projectId],
  )
  const groups = new Map<string, { tool: string, rule: string, kind: string, ids: string[], paths: (string | null)[], explanations: string[] }>()
  for (const r of rows) {
    const out = r.output as { suggestion?: unknown, reasons?: { kind?: unknown, explanation?: unknown, cited?: unknown }[] } | null
    if (out?.suggestion !== 'likely-false-positive' || !Array.isArray(out.reasons)) continue
    const cited = out.reasons.find(x => x?.cited === true && typeof x.kind === 'string' && x.kind !== 'real-risk' && x.kind !== 'other')
    if (!cited) continue
    const key = `${r.tool}\u0000${r.rule_id}\u0000${String(cited.kind)}`
    const g = groups.get(key) ?? { tool: r.tool, rule: r.rule_id, kind: String(cited.kind), ids: [], paths: [], explanations: [] }
    g.ids.push(r.id)
    g.paths.push(r.path)
    if (typeof cited.explanation === 'string' && g.explanations.length < 1) g.explanations.push(cited.explanation.slice(0, 400))
    groups.set(key, g)
  }
  const out: RuleProposal[] = []
  for (const g of groups.values()) {
    if (g.ids.length < PROPOSAL_MIN) continue
    const path = commonDirGlob(g.paths)
    const match: RuleMatch = { tool: MODULE_ID_RE.test(g.tool) ? g.tool : undefined, rule: g.rule.slice(0, 255), ...(path ? { path } : {}) }
    if (!match.tool) delete match.tool
    out.push({
      source: 'triage-finding', project_id: projectId, match, action: 'false-positive', reason_kind: g.kind,
      count: g.ids.length, finding_ids: g.ids.slice(0, 50), reason: g.explanations[0] ?? g.kind,
    })
  }
  return out.sort((a, b) => b.count - a.count).slice(0, 20)
}
