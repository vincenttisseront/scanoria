// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Exceptions motivées et datées par projet (§ 6.1), soumises à approbation
// (F5, J15, contrat 27 de la 0.7) :
// - requestException : toute identité (personne, jeton d'API, commentaire de
//   PR, import depuis un outil, configuration en code) DEMANDE ; la demande
//   n'a aucun effet sur le verdict tant qu'elle n'est pas approuvée ;
// - decideException : seul un administrateur humain et actif décide, s'il
//   n'est ni le demandeur ni un auteur du commit analysé ; l'IA, un jeton,
//   une application de forge, un compte « agent » ou « bot » ne décident
//   jamais ;
// - jamais d'exception pour un avis ou un résultat malveillant (H4), ni
//   contre un verrou de profil (G8, voir locks.ts) ;
// - après une approbation, reevaluateProject recalcule sans réanalyse le
//   verdict des dernières analyses du projet, puis appelle les écouteurs
//   onVerdictChanged (le chantier D y republie les statuts de forge).
// Toute demande et toute décision écrivent une ligne d'audit. Une exception
// échue ou révoquée cesse de s'appliquer d'elle-même (le gate ne lit que les
// exceptions « approved », non révoquées et non échues).

import { z } from 'zod'
import { ExceptionTargets, VerdictDetails, type ExceptionKind } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { writeAudit, type AuditActor } from '../utils/audit'
import { redact } from './redact'
import { moduleLocked, projectLocks, secretsLocked } from './locks'
import { evaluateGate } from '../gates/evaluate'
import { applyApprovedAcceptance, findingAuthors } from './triage'

/** Durée maximale d'une exception : elle doit être revue au moins une fois par an. */
export const MAX_EXCEPTION_DAYS = 366
/** Avis d'échéance : une exception approuvée qui expire dans ce délai est signalée une fois. */
export const EXPIRY_NOTICE_DAYS = 14

/** Date réelle au format AAAA-MM-JJ (le 31 novembre est refusé). */
export function isValidDay(value: string): boolean {
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)) return false
  const d = new Date(`${value}T00:00:00Z`)
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value
}

const dateSchema = z.string().refine(isValidDay)

const base = {
  project_id: z.string().uuid(),
  reason: z.string().trim().min(3).max(2000),
  expires_on: dateSchema,
  /** Analyse d'où vient la demande (lien « demander une exception ») : ses auteurs sont exclus de l'approbation. */
  scan_id: z.string().uuid().optional(),
}
export const exceptionCreateSchema = z.discriminatedUnion('kind', [
  z.strictObject({ ...base, kind: z.literal('path'), target: ExceptionTargets.path }),
  z.strictObject({ ...base, kind: z.literal('rule'), target: ExceptionTargets.rule }),
  z.strictObject({ ...base, kind: z.literal('vuln'), target: ExceptionTargets.vuln }),
  z.strictObject({ ...base, kind: z.literal('finding'), target: ExceptionTargets.finding }),
  z.strictObject({ ...base, kind: z.literal('module'), target: ExceptionTargets.module }),
])

export const decisionSchema = z.strictObject({
  decision: z.enum(['approved', 'refused']),
  reason: z.string().trim().min(3).max(2000),
})

export const REQUESTED_VIA = ['console', 'api', 'pr-comment', 'tool-import', 'config'] as const
export type RequestedVia = (typeof REQUESTED_VIA)[number]

export type ExceptionErrorCode
  = | 'E_NOT_FOUND' | 'E_MALICIOUS' | 'E_VALIDATION' | 'E_LOCKED'
    | 'E_NOT_PENDING' | 'E_DECIDER_NOT_ALLOWED' | 'E_EXPIRED'

/** Pourquoi un décideur est refusé (J15). */
export type DeciderRefusal = 'not-admin' | 'not-human' | 'inactive' | 'requester' | 'commit-author'

export class ExceptionError extends Error {
  constructor(public code: ExceptionErrorCode, public detail: string | null = null) {
    super(code)
  }
}

/** Date du jour (UTC) décalée de n jours, au format AAAA-MM-JJ. */
export function isoDay(offsetDays = 0, now = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offsetDays)).toISOString().slice(0, 10)
}

export interface ExceptionRow {
  id: string
  project_id: string
  project_slug: string
  project_name: string
  kind: string
  target: Record<string, unknown>
  reason: string
  expires_on: string
  status: 'requested' | 'approved' | 'refused'
  requested_via: RequestedVia
  requester_label: string | null
  requester_is_human: boolean
  commit_authors: string[]
  created_by: string | null
  created_at: string
  decided_by: string | null
  decided_at: string | null
  decision_reason: string | null
  revoked_at: string | null
  revoked_by: string | null
  expiry_notified_at: string | null
  /** Approuvée, non révoquée, non échue : appliquée par le gate. */
  active: boolean
  expired: boolean
  /** Approuvée et échéance dans EXPIRY_NOTICE_DAYS jours au plus. */
  expiring_soon: boolean
}

const TS = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

const COLUMNS = `e.id, e.project_id, p.slug AS project_slug, p.name AS project_name, e.kind, e.target, e.reason,
  to_char(e.expires_on, 'YYYY-MM-DD') AS expires_on, e.status, e.requested_via, e.requester_label,
  e.requester_is_human, e.commit_authors,
  uc.username AS created_by, ${TS('e.created_at')} AS created_at,
  ud.username AS decided_by, ${TS('e.decided_at')} AS decided_at, e.decision_reason,
  ${TS('e.revoked_at')} AS revoked_at, ur.username AS revoked_by, ${TS('e.expiry_notified_at')} AS expiry_notified_at,
  (e.status = 'approved' AND e.revoked_at IS NULL AND e.expires_on >= current_date) AS active,
  (e.revoked_at IS NULL AND e.expires_on < current_date) AS expired,
  (e.status = 'approved' AND e.revoked_at IS NULL AND e.expires_on >= current_date
     AND e.expires_on <= current_date + ${EXPIRY_NOTICE_DAYS}) AS expiring_soon`

const FROM = `FROM exceptions e JOIN projects p ON p.id = e.project_id
  LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ud ON ud.id = e.decided_by
  LEFT JOIN users ur ON ur.id = e.revoked_by`

/** Exceptions d'un projet : en cours (demandées ou approuvées, non révoquées, non échues) ou toutes. */
export async function listExceptions(db: Queryable, projectId: string, includeInactive: boolean): Promise<ExceptionRow[]> {
  const r = await db.query<ExceptionRow>(
    `SELECT ${COLUMNS} ${FROM}
      WHERE e.project_id = $1
        ${includeInactive ? '' : `AND e.status <> 'refused' AND e.revoked_at IS NULL AND e.expires_on >= current_date`}
      ORDER BY (e.status = 'requested') DESC, e.created_at DESC LIMIT 500`,
    [projectId],
  )
  return r.rows
}

/** Demandes en attente de décision, tous projets (page « Exceptions à approuver »). */
export async function listPendingExceptions(db: Queryable, projectId?: string): Promise<ExceptionRow[]> {
  const r = await db.query<ExceptionRow>(
    `SELECT ${COLUMNS} ${FROM}
      WHERE e.status = 'requested' AND e.revoked_at IS NULL AND ($1::uuid IS NULL OR e.project_id = $1)
      ORDER BY e.created_at LIMIT 500`,
    [projectId ?? null],
  )
  return r.rows
}

/** Compteur de la navigation : demandes en attente et non échues. */
export async function countPendingExceptions(db: Queryable): Promise<number> {
  const r = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM exceptions e JOIN projects p ON p.id = e.project_id
      WHERE e.status = 'requested' AND e.revoked_at IS NULL AND e.expires_on >= current_date AND p.archived_at IS NULL`,
  )
  return r.rows[0]?.n ?? 0
}

/** Exceptions approuvées qui expirent bientôt (bandeau d'échéance). */
export async function listExpiringExceptions(db: Queryable, projectId?: string): Promise<ExceptionRow[]> {
  const r = await db.query<ExceptionRow>(
    `SELECT ${COLUMNS} ${FROM}
      WHERE e.status = 'approved' AND e.revoked_at IS NULL AND e.expires_on >= current_date
        AND e.expires_on <= current_date + ${EXPIRY_NOTICE_DAYS} AND ($1::uuid IS NULL OR e.project_id = $1)
      ORDER BY e.expires_on, e.id LIMIT 200`,
    [projectId ?? null],
  )
  return r.rows
}

export async function getException(db: Queryable, id: string): Promise<ExceptionRow | null> {
  const r = await db.query<ExceptionRow>(`SELECT ${COLUMNS} ${FROM} WHERE e.id = $1`, [id])
  return r.rows[0] ?? null
}

// ---------------------------------------------------------------- demande

export interface ExceptionRequestInput {
  project_id: string
  kind: ExceptionKind | string
  target: Record<string, unknown>
  reason: string
  expires_on: string
  requested_via: RequestedVia
  /** Nom affiché du demandeur : identifiant, « api-token:scn_ab12 », login de forge… */
  requester_label: string
  /** Faux pour un jeton, une application de forge, un compte « agent » ou « bot ». */
  requester_is_human: boolean
  /** Compte de la console, s'il y en a un (null pour un jeton ou un commentaire de forge non relié). */
  requester_user_id: number | null
  /** Auteurs du commit analysé (identifiants ou adresses), exclus de l'approbation. */
  commit_authors: string[]
  /** Analyse d'origine : l'auteur de sa PR est ajouté aux auteurs exclus. */
  scan_id?: string
}

const MAX_AUTHORS = 20

function normalizeAuthors(list: unknown[]): string[] {
  const out = new Set<string>()
  for (const a of list) {
    if (typeof a !== 'string') continue
    const v = a.trim().replace(/^@/, '').slice(0, 255)
    if (v) out.add(v)
    if (out.size >= MAX_AUTHORS) break
  }
  return [...out]
}

/**
 * Cible valide, pas de malveillant (H4), pas contre un verrou (G8). Appelé à
 * la demande et de nouveau à l'approbation (un verrou a pu être posé entre-temps).
 */
async function checkAllowed(db: Queryable, projectId: string, kind: string, target: Record<string, unknown>): Promise<void> {
  const schema = (ExceptionTargets as Record<string, z.ZodType>)[kind]
  if (!schema || !schema.safeParse(target).success) throw new ExceptionError('E_VALIDATION', 'target')
  // H4 : aucun avis MAL- ne s'exempte, ni par avis ni par règle (le quality gate
  // ignore de plus toute exception pour un résultat malveillant).
  if ((kind === 'vuln' && /^MAL-/i.test(String(target.vuln_id)))
    || (kind === 'rule' && /^MAL-/i.test(String(target.rule_id)))) throw new ExceptionError('E_MALICIOUS')
  const locks = await projectLocks(db, projectId)
  if (kind === 'finding') {
    const f = await db.query<{ malicious: boolean, secret_type: string | null }>(
      'SELECT malicious, secret_type FROM findings WHERE id = $1 AND project_id = $2', [target.finding_id, projectId])
    if (!f.rows[0]) throw new ExceptionError('E_NOT_FOUND')
    if (f.rows[0].malicious) throw new ExceptionError('E_MALICIOUS')
    if (f.rows[0].secret_type && secretsLocked(locks)) throw new ExceptionError('E_LOCKED', 'secrets')
  }
  if (kind === 'module' && await moduleLocked(locks, String(target.module_id))) throw new ExceptionError('E_LOCKED', 'module')
}

/** Contrat 27 : dépose une demande ; elle ne s'applique qu'une fois approuvée. */
export async function requestException(db: Queryable, input: ExceptionRequestInput, today = isoDay()): Promise<ExceptionRow> {
  const reason = typeof input.reason === 'string' ? input.reason.trim() : ''
  if (reason.length < 3 || reason.length > 2000) throw new ExceptionError('E_VALIDATION', 'reason')
  const max = isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))
  if (!isValidDay(input.expires_on) || input.expires_on < today || input.expires_on > max) throw new ExceptionError('E_VALIDATION', 'expires_on')
  if (!(REQUESTED_VIA as readonly string[]).includes(input.requested_via)) throw new ExceptionError('E_VALIDATION', 'requested_via')
  const label = typeof input.requester_label === 'string' ? input.requester_label.trim().slice(0, 255) : ''
  if (!label) throw new ExceptionError('E_VALIDATION', 'requester_label')
  const project = await db.query('SELECT 1 FROM projects WHERE id = $1', [input.project_id])
  if (!project.rowCount) throw new ExceptionError('E_NOT_FOUND')
  await checkAllowed(db, input.project_id, input.kind, input.target)

  // Une personne n'est humaine que si son compte l'est : un compte « agent » ou « bot » ne l'est jamais.
  let human = input.requester_is_human === true
  if (input.requester_user_id !== null) {
    const u = await db.query<{ kind: string }>('SELECT kind FROM users WHERE id = $1', [input.requester_user_id])
    if (!u.rows[0]) throw new ExceptionError('E_NOT_FOUND')
    human = human && u.rows[0].kind === 'human'
  }
  const authors: unknown[] = Array.isArray(input.commit_authors) ? [...input.commit_authors] : []
  if (input.scan_id) {
    const s = await db.query<{ author: string | null }>(
      `SELECT pull_request->>'author' AS author FROM scans WHERE id = $1 AND project_id = $2`, [input.scan_id, input.project_id])
    if (!s.rows[0]) throw new ExceptionError('E_NOT_FOUND')
    if (s.rows[0].author) authors.push(s.rows[0].author)
  }
  const r = await db.query<{ id: string }>(
    `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_by, status, decided_at,
                             requested_via, requester_label, requester_is_human, commit_authors)
     VALUES ($1, $2, $3, $4, $5::date, $6, 'requested', NULL, $7, $8, $9, $10) RETURNING id`,
    [input.project_id, input.kind, JSON.stringify(input.target), redact(reason), input.expires_on, input.requester_user_id,
      input.requested_via, label, human, normalizeAuthors(authors)],
  )
  const row = (await getException(db, r.rows[0]!.id))!
  await writeAudit(db, {
    actor: input.requester_user_id !== null
      ? { type: 'user', userId: input.requester_user_id, username: label }
      : { type: 'system', username: label },
    action: 'exception.request', outcome: 'success', targetType: 'exception', targetId: row.id,
    details: {
      project_id: row.project_id, kind: row.kind, target: row.target, reason: row.reason, expires_on: row.expires_on,
      requested_via: row.requested_via, requester_is_human: row.requester_is_human, commit_authors: row.commit_authors,
    },
  })
  return row
}

/**
 * « Accepter » un résultat depuis la console : une demande d'exception de type
 * « finding » (requested_via « console »), jamais un statut posé directement.
 * Les auteurs des commits où le résultat a été vu sont exclus de l'approbation.
 * Une demande déjà en attente pour ce résultat est renvoyée telle quelle.
 */
export async function requestFindingAcceptance(db: Queryable, findingId: string, user: { id: number, username: string },
  body: { reason: string, until: string }, today = isoDay()): Promise<{ request: ExceptionRow, created: boolean }> {
  const f = await db.query<{ project_id: string }>('SELECT project_id FROM findings WHERE id = $1 FOR UPDATE', [findingId])
  if (!f.rows[0]) throw new ExceptionError('E_NOT_FOUND')
  const pending = await db.query<{ id: string }>(
    `SELECT id FROM exceptions
      WHERE project_id = $1 AND kind = 'finding' AND target->>'finding_id' = $2 AND status = 'requested' AND revoked_at IS NULL
      ORDER BY created_at LIMIT 1`, [f.rows[0].project_id, findingId])
  if (pending.rows[0]) return { request: (await getException(db, pending.rows[0].id))!, created: false }
  const request = await requestException(db, {
    project_id: f.rows[0].project_id, kind: 'finding', target: { finding_id: findingId },
    reason: body.reason, expires_on: body.until, requested_via: 'console',
    requester_label: user.username, requester_is_human: true, requester_user_id: user.id,
    commit_authors: await findingAuthors(db, findingId),
  }, today)
  return { request, created: true }
}

// ---------------------------------------------------------------- décision

export interface Decider {
  id: number
  username: string
  email: string | null
  role: string
  kind: string
  is_active: boolean
}

async function loadDecider(db: Queryable, userId: number): Promise<Decider | null> {
  const r = await db.query<Decider>('SELECT id::int AS id, username, email, role, kind, is_active FROM users WHERE id = $1', [userId])
  return r.rows[0] ?? null
}

const same = (a: string | null | undefined, b: string | null | undefined) =>
  !!a && !!b && a.trim().replace(/^@/, '').toLowerCase() === b.trim().replace(/^@/, '').toLowerCase()

/**
 * Règles fixes de J15, dans l'ordre : administrateur, humain, actif, ni le
 * demandeur (compte ou libellé), ni un auteur du commit analysé (identifiant
 * ou adresse, sans tenir compte de la casse). null = peut décider.
 */
export function deciderRefusal(
  decider: Decider,
  ex: { created_by_id: number | null, requester_label: string | null, commit_authors: string[] },
): DeciderRefusal | null {
  if (decider.role !== 'admin') return 'not-admin'
  if (decider.kind !== 'human') return 'not-human'
  if (!decider.is_active) return 'inactive'
  if (ex.created_by_id !== null && ex.created_by_id === decider.id) return 'requester'
  if (same(ex.requester_label, decider.username) || same(ex.requester_label, decider.email)) return 'requester'
  if (ex.commit_authors.some(a => same(a, decider.username) || same(a, decider.email))) return 'commit-author'
  return null
}

export interface DecisionInput {
  decision: 'approved' | 'refused'
  reason: string
  deciderUserId: number
  ip?: string | null
}

/**
 * Contrat 27 : décision sur une demande. À appeler dans une transaction ; la
 * réévaluation des verdicts (reevaluateProject) se fait APRÈS la validation
 * de la transaction, par l'appelant (voir decideAndReevaluate).
 */
interface PendingRow {
  project_id: string
  kind: string
  target: Record<string, unknown>
  status: string
  revoked: boolean
  expires_on: string
  created_by_id: number | null
  requester_label: string | null
  commit_authors: string[]
  reason: string
}

export async function decideException(db: Queryable, id: string, input: DecisionInput, today = isoDay()): Promise<ExceptionRow> {
  const reason = typeof input.reason === 'string' ? input.reason.trim() : ''
  if (reason.length < 3 || reason.length > 2000) throw new ExceptionError('E_VALIDATION', 'reason')
  if (input.decision !== 'approved' && input.decision !== 'refused') throw new ExceptionError('E_VALIDATION', 'decision')
  const cur = await db.query<PendingRow>(
    `SELECT project_id, kind, target, status, revoked_at IS NOT NULL AS revoked, to_char(expires_on, 'YYYY-MM-DD') AS expires_on,
            created_by::int AS created_by_id, requester_label, commit_authors, reason
       FROM exceptions WHERE id = $1 FOR UPDATE`, [id])
  const ex = cur.rows[0]
  if (!ex) throw new ExceptionError('E_NOT_FOUND')
  if (ex.status !== 'requested' || ex.revoked) throw new ExceptionError('E_NOT_PENDING')
  const decider = await loadDecider(db, input.deciderUserId)
  if (!decider) throw new ExceptionError('E_DECIDER_NOT_ALLOWED', 'not-admin')
  const refusal = deciderRefusal(decider, ex)
  if (refusal) throw new ExceptionError('E_DECIDER_NOT_ALLOWED', refusal)
  if (input.decision === 'approved') {
    if (ex.expires_on < today) throw new ExceptionError('E_EXPIRED')
    await checkAllowed(db, ex.project_id, ex.kind, ex.target)
  }
  await db.query(
    `UPDATE exceptions SET status = $2, decided_by = $3, decided_at = now(), decision_reason = $4 WHERE id = $1`,
    [id, input.decision, decider.id, redact(reason)],
  )
  const row = (await getException(db, id))!
  await writeAudit(db, {
    actor: { type: 'user', userId: decider.id, username: decider.username, ip: input.ip ?? null },
    action: input.decision === 'approved' ? 'exception.approve' : 'exception.refuse',
    outcome: 'success', targetType: 'exception', targetId: id,
    details: {
      project_id: row.project_id, kind: row.kind, target: row.target, expires_on: row.expires_on,
      requested_by: row.created_by ?? row.requester_label, requested_via: row.requested_via, decision_reason: row.decision_reason,
    },
  })
  // Seul chemin qui pose « accepted » sur un résultat : l'approbation d'une demande.
  if (input.decision === 'approved' && ex.kind === 'finding') {
    const findingId = String(ex.target.finding_id)
    const applied = await applyApprovedAcceptance(db, findingId, { until: ex.expires_on, reason: ex.reason, deciderId: decider.id })
    if (applied) {
      await writeAudit(db, {
        actor: { type: 'user', userId: decider.id, username: decider.username, ip: input.ip ?? null },
        action: 'finding.status', outcome: 'success', targetType: 'finding', targetId: findingId,
        details: { project_id: ex.project_id, from: applied.before.status, to: 'accepted', until: ex.expires_on, exception_id: id },
      })
    }
  }
  return row
}

/** Audit d'une décision refusée (écrit hors de la transaction annulée). */
export async function auditDecisionDenied(db: Queryable, id: string, actor: AuditActor, err: ExceptionError): Promise<void> {
  await writeAudit(db, {
    actor, action: 'exception.decide', outcome: 'denied', targetType: 'exception', targetId: id,
    details: { code: err.code, reason_code: err.detail },
  })
}

/** Révocation (l'historique est gardé). Sans effet sur une exception déjà révoquée. */
export async function revokeException(db: Queryable, id: string, userId: number | null): Promise<ExceptionRow> {
  const r = await db.query<{ kind: string, target: Record<string, unknown>, status: string, expires_on: string }>(
    `UPDATE exceptions SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL
     RETURNING kind, target, status, to_char(expires_on, 'YYYY-MM-DD') AS expires_on`, [id, userId])
  const ex = r.rows[0]
  // Révoquer l'approbation d'un résultat accepté le rend de nouveau bloquant.
  if (ex && ex.kind === 'finding' && ex.status === 'approved') {
    await db.query(
      `UPDATE findings SET status = 'new', status_reason = NULL, status_until = NULL, status_by = $3, status_at = now(), updated_at = now()
        WHERE id::text = $1 AND status = 'accepted' AND status_until = $2::date`,
      [String(ex.target.finding_id), ex.expires_on, userId])
  }
  const row = await getException(db, id)
  if (!row) throw new ExceptionError('E_NOT_FOUND')
  return row
}

// ---------------------------------------------------------------- réévaluation

export type VerdictListener = (db: Queryable, scanId: string) => Promise<void>
const listeners: VerdictListener[] = []

/** Contrat 27 : écouteur appelé pour chaque analyse dont le verdict change à une réévaluation. */
export function onVerdictChanged(listener: VerdictListener): void {
  if (!listeners.includes(listener)) listeners.push(listener)
}

/** Tests : retire tous les écouteurs. */
export function clearVerdictListeners(): void {
  listeners.length = 0
}

/** Au plus autant d'analyses réévaluées à la fois (une par branche ou par PR). */
const MAX_REEVALUATED = 100

export interface Reevaluation {
  scan_id: string
  before: string | null
  after: string
}

type Evaluate = (db: Queryable, scanId: string) => Promise<VerdictDetails>

/** JSON à clés triées : jsonb ne garde pas l'ordre des clés, la comparaison ne doit pas en dépendre. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o).filter(k => o[k] !== undefined).sort((a, b) => a.localeCompare(b)).map(k => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v ?? null)
}

/** Le détail compte, sans l'heure de l'évaluation : une raison levée change le statut publié même à verdict égal. */
function comparable(d: unknown): string {
  if (!d || typeof d !== 'object') return ''
  const { evaluated_at: _e, ...rest } = d as Record<string, unknown>
  return canonical(rest)
}

/**
 * Contrat 27 : recalcule, SANS réanalyse, le verdict de la dernière analyse
 * terminée de chaque branche et de chaque PR du projet, enregistre ceux qui
 * changent, puis appelle les écouteurs. Une erreur d'écouteur est journalisée
 * et n'arrête ni les autres écouteurs ni les autres analyses.
 */
export async function reevaluateProject(db: Queryable, projectId: string, evaluate?: Evaluate): Promise<Reevaluation[]> {
  const evalFn: Evaluate = evaluate ?? evaluateGate
  const { rows } = await db.query<{ id: string, verdict: string | null, verdict_details: unknown }>(
    `SELECT id, verdict, verdict_details FROM (
       SELECT DISTINCT ON (s.ref, COALESCE(s.pull_request->>'number', '')) s.id, s.verdict, s.verdict_details, s.finished_at
         FROM scans s
        WHERE s.project_id = $1 AND s.status = 'done' AND s.verdict IS NOT NULL AND s.trigger <> 'trial'
        ORDER BY s.ref, COALESCE(s.pull_request->>'number', ''), s.finished_at DESC NULLS LAST, s.queued_at DESC
     ) x ORDER BY finished_at DESC NULLS LAST LIMIT ${MAX_REEVALUATED}`,
    [projectId],
  )
  const changed: Reevaluation[] = []
  for (const s of rows) {
    let details: VerdictDetails
    try {
      details = VerdictDetails.parse(await evalFn(db, s.id))
    }
    catch (e) {
      console.error(`[exceptions] scan ${s.id}: reevaluation failed: ${(e as Error).message}`)
      continue
    }
    if (details.verdict === s.verdict && comparable(details) === comparable(s.verdict_details)) continue
    await db.query('UPDATE scans SET verdict = $2, verdict_details = $3 WHERE id = $1', [s.id, details.verdict, JSON.stringify(details)])
    changed.push({ scan_id: s.id, before: s.verdict, after: details.verdict })
  }
  if (changed.length) {
    await writeAudit(db, {
      actor: { type: 'system' }, action: 'gate.reevaluate', outcome: 'success', targetType: 'project', targetId: projectId,
      details: { scans: changed.slice(0, 50) },
    })
  }
  for (const c of changed) {
    for (const l of [...listeners]) {
      try {
        await l(db, c.scan_id)
      }
      catch (e) {
        console.error(`[exceptions] scan ${c.scan_id}: verdict listener failed: ${(e as Error).message}`)
      }
    }
  }
  return changed
}

// ---------------------------------------------------------------- échéance

/**
 * Avis d'échéance (F5) : une exception approuvée qui expire dans
 * EXPIRY_NOTICE_DAYS jours est signalée une fois (expiry_notified_at et une
 * ligne d'audit) ; la console l'affiche en bandeau, les notifications
 * arrivent en 0.9 (F10). Une exception échue redevient bloquante d'elle-même.
 */
export async function notifyExpiringExceptions(db: Queryable): Promise<number> {
  const r = await db.query<{ id: string, project_id: string, expires_on: string }>(
    `UPDATE exceptions SET expiry_notified_at = now()
      WHERE status = 'approved' AND revoked_at IS NULL AND expiry_notified_at IS NULL
        AND expires_on >= current_date AND expires_on <= current_date + ${EXPIRY_NOTICE_DAYS}
      RETURNING id, project_id, to_char(expires_on, 'YYYY-MM-DD') AS expires_on`,
  )
  for (const e of r.rows) {
    await writeAudit(db, {
      actor: { type: 'system' }, action: 'exception.expiry-notice', outcome: 'success', targetType: 'exception', targetId: e.id,
      details: { project_id: e.project_id, expires_on: e.expires_on },
    })
  }
  return r.rowCount ?? 0
}
