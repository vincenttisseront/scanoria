// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Demandes d'exception venues du dépôt (.scanoria.yml, J8) ou d'une reprise de
// l'existant (J5) : toujours des DEMANDES (status « requested »), jamais des
// exceptions approuvées. Elles suivent le circuit F5 (contrat 27, chantier B) :
// un administrateur humain les approuve ou les refuse. Une identité non humaine
// (dépôt, outil importé) demande sans jamais approuver.
//
// Chaque demande passe par requestException (contrat 27) : mêmes contrôles
// (H4, verrous G8), même audit. Une demande déjà connue (même cible, quel que
// soit son statut) n'est jamais recréée, pour qu'un refus ne revienne pas à
// chaque analyse.

import { ExceptionTargets, type ExceptionKind } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { ExceptionError, MAX_EXCEPTION_DAYS, isValidDay, isoDay, requestException } from '../findings/exceptions'

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
  /** Analyse d'origine : l'auteur de sa PR ne peut pas approuver (J15). */
  scanId?: string
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
    if (p.dryRun) {
      out.statuses.push('new')
      out.created.push({ id: '', kind: r.kind, target })
      continue
    }
    try {
      const row = await requestException(db, {
        project_id: p.projectId, kind: r.kind, target, reason: r.reason, expires_on: r.expires_on,
        requested_via: p.via, requester_label: p.requesterLabel.slice(0, 255), requester_is_human: false,
        requester_user_id: null, commit_authors: p.commitAuthors ?? [], scan_id: p.scanId,
      }, today)
      out.statuses.push('new')
      out.created.push({ id: row.id, kind: r.kind, target })
    }
    catch (e) {
      if (!(e instanceof ExceptionError)) throw e
      const why: RequestSkip = e.code === 'E_MALICIOUS' ? 'malicious' : e.code === 'E_LOCKED' ? 'locked' : 'invalid'
      out.skipped.push({ kind: r.kind, target, why })
      out.statuses.push(why)
    }
  }
  return out
}
