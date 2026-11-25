// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J15 côté forge → contrat 27 (circuit des exceptions, chantier B) :
// requestException(db, input) de server/findings/exceptions.ts, appelée avec
// requested_via 'pr-comment' et l'identité de la forge comme demandeur. Tant
// que le circuit de B n'est pas sur main, une demande équivalente est
// enregistrée ici (statut 'requested', aucune décision), selon le schéma figé
// de la migration 013 ; l'approbation reste celle de la console.

import type { Queryable } from '../utils/db'
import * as exceptions from '../findings/exceptions'
import { redact } from '../findings/redact'

export interface PrExceptionRequest {
  projectId: string
  scanId: string
  findingId: string
  until: string
  reason: string
  /** « forgejo:login » : identité de la forge, jamais un compte de la console. */
  requesterLabel: string
  commitAuthors: string[]
}

export type PrExceptionOutcome = { ok: true, id: string } | { ok: false, code: 'E_MALICIOUS' | 'E_VALIDATION' | 'E_NOT_FOUND' | 'E_LOCKED' }

type RequestException = (db: Queryable, input: Record<string, unknown>) => Promise<{ id: string }>

function errorCode(err: unknown): PrExceptionOutcome | null {
  const code = (err as { code?: unknown } | null)?.code
  return code === 'E_MALICIOUS' || code === 'E_VALIDATION' || code === 'E_NOT_FOUND' || code === 'E_LOCKED' ? { ok: false, code } : null
}

export async function requestPrException(db: Queryable, req: PrExceptionRequest): Promise<PrExceptionOutcome> {
  const input = {
    project_id: req.projectId,
    kind: 'finding',
    target: { finding_id: req.findingId },
    reason: req.reason,
    expires_on: req.until,
    requested_via: 'pr-comment',
    requester_label: req.requesterLabel.slice(0, 255),
    // Personne derrière le compte de forge, mais jamais un compte de la console : demandeur seulement.
    requester_is_human: false,
    requester_user_id: null,
    commit_authors: req.commitAuthors.slice(0, 20),
    scan_id: req.scanId,
  }
  const fn = (exceptions as unknown as { requestException?: RequestException }).requestException
  if (typeof fn === 'function') {
    try {
      return { ok: true, id: (await fn(db, input)).id }
    }
    catch (err) {
      const known = errorCode(err)
      if (known) return known
      throw err
    }
  }
  return fallbackRequest(db, req)
}

/** Demande enregistrée directement (avant la fusion du chantier B), mêmes règles de fond. */
async function fallbackRequest(db: Queryable, req: PrExceptionRequest): Promise<PrExceptionOutcome> {
  const today = exceptions.isoDay()
  const max = exceptions.isoDay(exceptions.MAX_EXCEPTION_DAYS)
  if (!exceptions.isValidDay(req.until) || req.until < today || req.until > max) return { ok: false, code: 'E_VALIDATION' }
  const f = await db.query<{ malicious: boolean }>('SELECT malicious FROM findings WHERE id = $1 AND project_id = $2', [req.findingId, req.projectId])
  if (!f.rows[0]) return { ok: false, code: 'E_NOT_FOUND' }
  if (f.rows[0].malicious) return { ok: false, code: 'E_MALICIOUS' }
  const r = await db.query<{ id: string }>(
    `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_by, status, decided_at,
                             requested_via, requester_label, requester_is_human, commit_authors)
     VALUES ($1, 'finding', $2, $3, $4::date, NULL, 'requested', NULL, 'pr-comment', $5, false, $6) RETURNING id`,
    [req.projectId, JSON.stringify({ finding_id: req.findingId }), redact(req.reason), req.until, req.requesterLabel.slice(0, 255), req.commitAuthors.slice(0, 20)])
  return { ok: true, id: r.rows[0]!.id }
}
