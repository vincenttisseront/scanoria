// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aide commune des routes /api/rulesets/** : traduction des erreurs du
// magasin en réponses API, acteur de l'audit.

import type { H3Event } from 'h3'
import { apiError, clientAddress, type AuthContext } from '../utils/http'
import { RulesetError } from './store'

export function rulesetActor(event: H3Event, auth: AuthContext) {
  return { userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) ?? null }
}

export function mapRulesetError(err: unknown): never {
  if (err instanceof RulesetError) {
    const status = { E_NOT_FOUND: 404, E_VALIDATION: 400, E_PRECONDITION: 409, E_CONFLICT: 409 }[err.code]
    const code = err.code === 'E_CONFLICT' ? 'E_PRECONDITION' : err.code
    throw apiError(status, code, { reason: err.message, issues: err.issues.map(c => ({ path: 'content', code: c })) })
  }
  throw err
}
