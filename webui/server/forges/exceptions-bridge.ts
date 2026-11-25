// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// J15 côté forge → contrat 27 (circuit des exceptions, chantier B) :
// requestException(db, input) de server/findings/exceptions.ts, appelée avec
// requested_via 'pr-comment' et l'identité de la forge comme demandeur, jamais
// humaine au sens de la console : demande seulement (statut 'requested') ;
// l'approbation reste celle de la console, par une autre personne.

import type { Queryable } from '../utils/db'
import * as exceptions from '../findings/exceptions'

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

function errorCode(err: unknown): PrExceptionOutcome | null {
  const code = (err as { code?: unknown } | null)?.code
  return code === 'E_MALICIOUS' || code === 'E_VALIDATION' || code === 'E_NOT_FOUND' || code === 'E_LOCKED' ? { ok: false, code } : null
}

export async function requestPrException(db: Queryable, req: PrExceptionRequest): Promise<PrExceptionOutcome> {
  const input = {
    project_id: req.projectId,
    kind: 'finding' as const,
    target: { finding_id: req.findingId },
    reason: req.reason,
    expires_on: req.until,
    requested_via: 'pr-comment' as const,
    requester_label: req.requesterLabel.slice(0, 255),
    // Personne derrière le compte de forge, mais jamais un compte de la console : demandeur seulement.
    requester_is_human: false,
    requester_user_id: null,
    commit_authors: req.commitAuthors.slice(0, 20),
    scan_id: req.scanId,
  }
  try {
    return { ok: true, id: (await exceptions.requestException(db, input)).id }
  }
  catch (err) {
    const known = errorCode(err)
    if (known) return known
    throw err
  }
}
