// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Traduction des erreurs du circuit des exceptions (contrat 27) en erreurs
// HTTP à code stable, partagée par les routes de demande et de décision.

import { z } from 'zod'
import { ExceptionTargets } from '#shared/analysis'
import { apiError } from '../utils/http'
import { ExceptionError, isValidDay } from './exceptions'

/** Corps de POST /api/projects/:id/exception-requests (J15, demande depuis la CI). */
const base = {
  reason: z.string().trim().min(3).max(2000),
  expires_on: z.string().refine(isValidDay),
  scan_id: z.string().uuid().optional(),
  commit_authors: z.array(z.string().trim().min(1).max(255)).max(20).optional(),
}
export const exceptionRequestSchema = z.discriminatedUnion('kind', [
  z.strictObject({ ...base, kind: z.literal('path'), target: ExceptionTargets.path }),
  z.strictObject({ ...base, kind: z.literal('rule'), target: ExceptionTargets.rule }),
  z.strictObject({ ...base, kind: z.literal('vuln'), target: ExceptionTargets.vuln }),
  z.strictObject({ ...base, kind: z.literal('finding'), target: ExceptionTargets.finding }),
  z.strictObject({ ...base, kind: z.literal('module'), target: ExceptionTargets.module }),
])

export function exceptionHttpError(err: unknown): unknown {
  if (!(err instanceof ExceptionError)) return err
  switch (err.code) {
    case 'E_NOT_FOUND': return apiError(404, 'E_NOT_FOUND')
    case 'E_MALICIOUS': return apiError(409, 'E_MALICIOUS')
    case 'E_LOCKED': return apiError(409, 'E_LOCKED', { reason: err.detail })
    case 'E_NOT_PENDING': return apiError(409, 'E_NOT_PENDING')
    case 'E_EXPIRED': return apiError(409, 'E_EXPIRED')
    case 'E_DECIDER_NOT_ALLOWED': return apiError(403, 'E_DECIDER_NOT_ALLOWED', { reason: err.detail })
    default: return apiError(400, 'E_VALIDATION', { issues: [{ path: err.detail ?? '', code: 'invalid' }] })
  }
}
