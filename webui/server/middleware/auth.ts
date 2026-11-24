// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrôles communs à toute l'API /api :
// - en-têtes de sécurité ;
// - requêtes qui modifient : même origine exigée (Origin / Sec-Fetch-Site) ;
// - session (cookie) résolue, 401 hors routes publiques ;
// - jeton CSRF exigé (X-CSRF-Token) pour toute requête qui modifie avec session ;
// - changement de mot de passe imposé : seules les routes du compte restent ouvertes.

import { defineEventHandler, getCookie, getHeader, getRequestHost, setHeader } from 'h3'
import { getPool } from '../utils/db'
import { apiError, clientAddress } from '../utils/http'
import { getAuthSettings } from '../utils/settings'
import { CSRF_HEADER, SESSION_COOKIE, csrfTokenFor, resolveSession, safeEqual } from '../utils/sessions'
import { consoleReady, waitReady } from '../utils/runtime'

const PUBLIC = new Set(['GET /api/health', 'GET /api/about', 'GET /api/openapi.json', 'POST /api/auth/login', 'GET /api/auth/session'])
const PASSWORD_CHANGE_ALLOWED = new Set(['GET /api/auth/session', 'POST /api/auth/password', 'POST /api/auth/logout', 'GET /api/about'])
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

function sameOrigin(origin: string, host: string | undefined): boolean {
  try {
    return !!host && new URL(origin).host === host
  }
  catch {
    return false
  }
}

export default defineEventHandler(async (event) => {
  const path = event.path.split('?')[0] ?? ''
  if (!path.startsWith('/api/') && path !== '/api') return
  setHeader(event, 'cache-control', 'no-store')
  setHeader(event, 'x-content-type-options', 'nosniff')
  const method = event.method.toUpperCase()
  const key = `${method} ${path}`
  if (key === 'GET /api/health') return

  if (!consoleReady() && !(await waitReady(10_000))) throw apiError(503, 'E_UNAVAILABLE')

  if (!SAFE_METHODS.has(method)) {
    const site = getHeader(event, 'sec-fetch-site')
    if (site && site !== 'same-origin' && site !== 'none') throw apiError(403, 'E_ORIGIN')
    const origin = getHeader(event, 'origin')
    if (origin && !sameOrigin(origin, getRequestHost(event, { xForwardedHost: false }))) throw apiError(403, 'E_ORIGIN')
  }

  // Jeton d'API de la CI ou route publique, déjà traités par api-token.ts (0.3, chantier E).
  if (event.context.apiToken || event.context.gatesPublic) return

  const token = getCookie(event, SESSION_COOKIE)
  if (token) {
    const pool = getPool()
    const session = await resolveSession(pool, token, await getAuthSettings(pool))
    if (session) {
      event.context.auth = { user: session.user, tokenHash: session.tokenHash, csrf: csrfTokenFor(token) }
    }
  }
  clientAddress(event)

  const auth = event.context.auth
  if (!auth) {
    if (!PUBLIC.has(key)) throw apiError(401, 'E_UNAUTHENTICATED')
    return
  }
  if (!SAFE_METHODS.has(method) && key !== 'POST /api/auth/login') {
    const sent = getHeader(event, CSRF_HEADER)
    if (!sent || !safeEqual(sent, auth.csrf)) throw apiError(403, 'E_CSRF')
  }
  if (auth.user.mustChangePassword && !PASSWORD_CHANGE_ALLOWED.has(key)) {
    throw apiError(403, 'E_PASSWORD_CHANGE_REQUIRED')
  }
})
