// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Demandes d'exception venues du dépôt (.scanoria.yml, J8) ou d'une reprise de
// l'existant (J5) : toujours des DEMANDES (status « requested »), jamais des
// exceptions approuvées. Elles suivent le circuit F5 (contrat 27, chantier B) :
// un administrateur humain les approuve ou les refuse. Une identité non humaine
// (dépôt, outil importé) demande sans jamais approuver.
//
// Insertion conforme au schéma 013, isolée ici en attendant requestException
// (chantier B) ; une demande déjà connue (même cible, quel que soit son
// statut) n'est jamais recréée, pour qu'un refus ne revienne pas à chaque analyse.

import { ExceptionTargets, type ExceptionKind } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { MAX_EXCEPTION_DAYS, isValidDay, isoDay } from '../findings/exceptions'
import { redact } from '../findings/redact'

export type RequestVia = 'config' | 'tool-import'

export interface ExceptionRequestInput {
  kind: Exclude<ExceptionKind, 'finding'> | 'finding'
  target: Record<string, unknown>
  reason: string
  expires_on: string
}

export type RequestSkip = 'malicious' | 'invalid' | 'duplicate' | 'locked'

export interface RequestOutcome {
  created: { id: string, kind: string, target: Record<string, unknown> }[]
  skipped: { kind: string, target: Record<string, unknown>, why: RequestSkip }[]
  /** Sort de chaque demande, dans l'ordre reçu. */
  statuses: ('new' | RequestSkip)[]
}

/** Date de fin par défaut d'une demande importée : 90 jours. */
export const DEFAULT_IMPORT_DAYS = 90

/** Contrôle d'une demande ; null si elle est recevable. */
export function checkRequest(r: ExceptionRequestInput, today = isoDay(), lockedModules: string[] = []): RequestSkip | null {
  const target = ExceptionTargets[r.kind]?.safeParse(r.target)
  if (!target?.success) return 'invalid'
  const max = isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))
  if (!isValidDay(r.expires_on) || r.expires_on < today || r.expires_on > max) return 'invalid'
  if (r.reason.trim().length < 3 || r.reason.length > 2000) return 'invalid'
  // H4 : jamais d'exception pour un avis MAL-, ni par avis ni par règle.
  if ((r.kind === 'vuln' && /^MAL-/i.test(String(r.target.vuln_id))) || (r.kind === 'rule' && /^MAL-/i.test(String(r.target.rule_id)))) return 'malicious'
  // G8 : un module exigé par un verrou ne s'exempte pas.
  if (r.kind === 'module' && lockedModules.includes(String(r.target.module_id))) return 'locked'
  return null
}

/** Une demande ou exception de même cible existe-t-elle déjà (tout statut, non révoquée) ? Égalité jsonb. */
async function alreadyKnown(db: Queryable, projectId: string, kind: string, target: Record<string, unknown>): Promise<boolean> {
  const r = await db.query(
    'SELECT 1 FROM exceptions WHERE project_id = $1 AND kind = $2 AND target = $3::jsonb AND revoked_at IS NULL LIMIT 1',
    [projectId, kind, JSON.stringify(target)])
  return !!r.rowCount
}

/**
 * Dépose des demandes d'exception pour un projet. Chaque demande créée ou
 * écartée est rendue pour l'aperçu et l'audit ; dryRun n'écrit rien.
 */
export async function fileRequests(db: Queryable, p: {
  projectId: string
  via: RequestVia
  requesterLabel: string
  requests: ExceptionRequestInput[]
  commitAuthors?: string[]
  lockedModules?: string[]
  dryRun?: boolean
  today?: string
}): Promise<RequestOutcome> {
  const today = p.today ?? isoDay()
  const seen = new Set<string>()
  const out: RequestOutcome = { created: [], skipped: [], statuses: [] }
  for (const r of p.requests.slice(0, 500)) {
    const why = checkRequest(r, today, p.lockedModules)
    if (why) {
      out.skipped.push({ kind: r.kind, target: r.target, why })
      out.statuses.push(why)
      continue
    }
    const target = ExceptionTargets[r.kind].parse(r.target) as Record<string, unknown>
    const key = `${r.kind} ${JSON.stringify(Object.entries(target).sort(([a], [b]) => a.localeCompare(b)))}`
    if (seen.has(key) || await alreadyKnown(db, p.projectId, r.kind, target)) {
      out.skipped.push({ kind: r.kind, target, why: 'duplicate' })
      out.statuses.push('duplicate')
      continue
    }
    seen.add(key)
    out.statuses.push('new')
    if (p.dryRun) {
      out.created.push({ id: '', kind: r.kind, target })
      continue
    }
    const ins = await db.query<{ id: string }>(
      `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_by, status, requested_via,
                               requester_label, requester_is_human, decided_at, commit_authors)
       VALUES ($1, $2, $3, $4, $5::date, NULL, 'requested', $6, $7, false, NULL, $8) RETURNING id::text`,
      [p.projectId, r.kind, JSON.stringify(target), redact(r.reason.trim()), r.expires_on, p.via,
        p.requesterLabel.slice(0, 255), (p.commitAuthors ?? []).slice(0, 50)])
    out.created.push({ id: ins.rows[0]!.id, kind: r.kind, target })
  }
  return out
}
