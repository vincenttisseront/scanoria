// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Erreurs du tri d'un résultat (et des demandes d'acceptation qu'il dépose)
// traduites en erreurs HTTP à code stable ; chaque refus est audité, hors de
// la transaction annulée.

import type { Queryable } from '../utils/db'
import { apiError } from '../utils/http'
import { writeAudit, type AuditActor } from '../utils/audit'
import { TriageError } from './triage'
import { ExceptionError } from './exceptions'
import { exceptionHttpError } from './exceptions-http'

export async function triageHttpError(err: unknown, db: Queryable, actor: AuditActor, id: string, details: Record<string, unknown>): Promise<unknown> {
  if (err instanceof TriageError) {
    if (err.code === 'E_MALICIOUS') {
      await writeAudit(db, { actor, action: 'finding.status', outcome: 'denied', targetType: 'finding', targetId: id, details: { ...details, reason_code: 'malicious' } })
      return apiError(409, 'E_MALICIOUS')
    }
    if (err.code === 'E_TRIAGE_NOT_ALLOWED') {
      await writeAudit(db, { actor, action: 'finding.status', outcome: 'denied', targetType: 'finding', targetId: id, details: { ...details, reason_code: err.detail } })
      return apiError(403, 'E_TRIAGE_NOT_ALLOWED', { reason: err.detail })
    }
    if (err.code === 'E_NOT_SECRET') return apiError(409, 'E_NOT_SECRET')
    return apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code === 'E_NOT_FOUND' ? 'E_NOT_FOUND' : 'E_VALIDATION')
  }
  if (err instanceof ExceptionError && (err.code === 'E_MALICIOUS' || err.code === 'E_LOCKED')) {
    await writeAudit(db, { actor, action: 'finding.status', outcome: 'denied', targetType: 'finding', targetId: id, details: { ...details, reason_code: err.code === 'E_MALICIOUS' ? 'malicious' : `locked:${err.detail ?? ''}` } })
  }
  return exceptionHttpError(err)
}
