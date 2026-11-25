// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Erreurs à code stable des profils (traduites côté console sous profiles.errors.*).

import { createError } from 'h3'
import { ProfileError } from './service'
import { ProfileResolutionError } from './resolve'
import { AssignError } from './assign'

export function profileHttpError(err: unknown): never {
  if (err instanceof ProfileError) {
    throw createError({ statusCode: err.status, statusMessage: err.code, data: { code: err.code, ...err.details } })
  }
  if (err instanceof AssignError) {
    const status = err.code === 'E_PROFILE_LOOSER' ? 403 : err.code === 'E_PROFILE_ARCHIVED' ? 409 : 400
    throw createError({ statusCode: status, statusMessage: err.code, data: { code: err.code, slot: err.slot } })
  }
  if (err instanceof ProfileResolutionError) {
    throw createError({ statusCode: err.code === 'E_PROFILE_NOT_FOUND' ? 404 : 409, statusMessage: err.code, data: { code: err.code } })
  }
  throw err
}
