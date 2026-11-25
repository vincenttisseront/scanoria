// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Erreurs du générateur de règles (I12) → réponses de l'API.

import { RulegenError } from './rulegen'
import { apiError } from '../utils/http'

export function rulegenHttpError(err: unknown): unknown {
  if (!(err instanceof RulegenError)) return err
  switch (err.reason) {
    case 'unavailable': return apiError(503, 'E_UNAVAILABLE', { reason: err.reason })
    case 'not-found': return apiError(404, 'E_NOT_FOUND')
    case 'not-human': return apiError(403, 'E_FORBIDDEN', { reason: err.reason })
    default: return apiError(409, 'E_PRECONDITION', { reason: err.reason })
  }
}
