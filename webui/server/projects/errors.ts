// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Erreurs de l'API des projets et des forges : même forme que apiError
// ({statusCode, data: {code}}), codes propres traduits sous projects.errors.*.
// Aucune valeur saisie (jeton, clé, URL complète) n'est renvoyée.

import { createError } from 'h3'
import { ForgeError, type ForgeErrorCode } from '../forges/http'
import { SecretError } from '../utils/secrets'
import { GitUrlError } from './git-url'

export const PROJECT_ERROR_CODES = [
  'E_PROJECT_EXISTS', 'E_FORGE_NAME_TAKEN', 'E_GIT_URL', 'E_KNOWN_HOSTS', 'E_SSH_KEYSCAN', 'E_UPLOAD_MISSING', 'E_PROJECT_DISCOVERED',
  'E_ARCHIVE_FORMAT', 'E_CONFIRM', 'E_ARCHIVED', 'E_NO_FORGE_ACCESS', 'E_SECRET', 'E_FORGE_IN_USE',
  'E_FORGEAPP_STATE', 'E_FORGEAPP_CONSOLE_URL', 'E_FORGEAPP_INSTALLATION', 'E_FORGEAPP_KIND',
] as const
export type ProjectErrorCode = (typeof PROJECT_ERROR_CODES)[number] | ForgeErrorCode

export function projectError(statusCode: number, code: ProjectErrorCode, extra: Record<string, unknown> = {}) {
  return createError({ statusCode, statusMessage: code, data: { code, ...extra } })
}

const FORGE_STATUS: Record<ForgeErrorCode, number> = {
  E_FORGE_URL: 400,
  E_FORGE_INPUT: 400,
  E_FORGE_AUTH: 422,
  E_FORGE_NOT_FOUND: 422,
  E_FORGE_RATE_LIMITED: 429,
  E_FORGE_UNSUPPORTED: 501,
  E_FORGE_UNREACHABLE: 502,
  E_FORGE_DNS: 502,
  E_FORGE_BLOCKED: 502,
  E_FORGE_TLS: 502,
  E_FORGE_TIMEOUT: 502,
  E_FORGE_TOO_LARGE: 502,
  E_FORGE_REDIRECT: 502,
  E_FORGE_RESPONSE: 502,
}

/** Convertit les erreurs connues (forge, URL, secret) en erreurs HTTP ; relance les autres. */
export function mapProjectError(err: unknown): never {
  if (err instanceof ForgeError) throw projectError(FORGE_STATUS[err.code], err.code, {
    ...(err.status ? { forge_status: err.status } : {}),
    ...(err.detail ? { forge_detail: err.detail } : {}),
  })
  if (err instanceof GitUrlError) throw projectError(400, 'E_GIT_URL')
  if (err instanceof SecretError) throw projectError(500, 'E_SECRET')
  throw err
}
