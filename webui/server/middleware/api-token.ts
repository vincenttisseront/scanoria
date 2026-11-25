// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jetons d'API de la CI (ARCHITECTURE § 12.8). Passe avant auth.ts (ordre
// alphabétique des middlewares Nitro) :
// - « Authorization: Bearer … » n'est admis que sur les routes de la CI
//   (dépôt d'une analyse, verdict), et seulement pour le projet de l'appelant :
//   jeton d'API « scn_… » (empreinte comparée en temps constant, last_used_at)
//   ou, depuis la 0.8 (J4), jeton OIDC de la CI rattaché par une liaison ;
//   l'authentification passe par authenticateCi (contrat 41), avec limite de débit ;
// - badge SVG et client scanoria-scan : routes publiques (le badge vérifie
//   lui-même qu'il est activé pour le projet).
// Une requête authentifiée ici n'a pas de session : auth.ts la laisse passer,
// sans CSRF (aucun cookie en jeu).

import { defineEventHandler, getHeader, setHeader, type H3Event } from 'h3'
import { getPool } from '../utils/db'
import { apiError, clientAddress } from '../utils/http'
import { FixedWindowLimiter } from '../utils/ratelimit'
import { CiAuthError, authenticateCi, ciAuthHttpError } from '../ci/auth'
import { gateError } from '../gates/http'

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
const CI_ROUTES: { method: string, re: RegExp, project: boolean }[] = [
  { method: 'POST', re: new RegExp(`^/api/projects/(${UUID})/scans$`), project: true },
  { method: 'GET', re: new RegExp(`^/api/scans/(${UUID})/verdict$`), project: false },
  // J6 (0.6) : résultats externes téléversés par la CI (portée scan:create).
  { method: 'POST', re: new RegExp(`^/api/projects/(${UUID})/results$`), project: true },
  // J15 (0.7, B) : demande d'exception depuis la CI (identité non humaine : demande, jamais décision).
  { method: 'POST', re: new RegExp(`^/api/projects/(${UUID})/exception-requests$`), project: true },
]
const PUBLIC_ROUTES: { method: string, re: RegExp }[] = [
  { method: 'GET', re: /^\/api\/badges\/[a-z0-9][a-z0-9-]{0,62}\.svg$/ },
  { method: 'GET', re: /^\/api\/gates\/client$/ },
  // 0.7 (D, J1) : webhook de forge, authentifié par sa signature HMAC.
  { method: 'POST', re: /^\/api\/forges\/[0-9a-f-]{36}\/webhook$/ },
]

/** Par jeton : 300 requêtes par minute (attente active de plusieurs CI). */
export const tokenLimiter = new FixedWindowLimiter(300, 60_000)
/** Par adresse : 30 jetons refusés par tranche de 10 minutes. */
export const badTokenLimiter = new FixedWindowLimiter(30, 10 * 60_000)
/** Routes publiques : 300 requêtes par minute et par adresse. */
export const publicLimiter = new FixedWindowLimiter(300, 60_000)

function tooMany(event: H3Event, limiter: FixedWindowLimiter, key: string) {
  setHeader(event, 'retry-after', limiter.retryAfterSeconds(key))
  return apiError(429, 'E_RATE_LIMITED')
}

export default defineEventHandler(async (event) => {
  const path = event.path.split('?')[0] ?? ''
  if (!path.startsWith('/api/')) return
  const method = event.method.toUpperCase()
  const authz = getHeader(event, 'authorization')

  if (!authz || !/^bearer\s/i.test(authz)) {
    if (PUBLIC_ROUTES.some(r => r.method === method && r.re.test(path))) {
      const ip = clientAddress(event) ?? 'unknown'
      if (!publicLimiter.hit(ip)) throw tooMany(event, publicLimiter, ip)
      event.context.gatesPublic = true
    }
    return
  }

  const ip = clientAddress(event) ?? 'unknown'
  const route = CI_ROUTES.find(r => r.method === method && r.re.test(path))
  if (!route) throw gateError(403, 'E_TOKEN_SCOPE')

  const projectId = route.project ? route.re.exec(path)![1]!.toLowerCase() : null
  let auth
  try {
    auth = await authenticateCi(event, getPool(), projectId)
  }
  catch (err) {
    if (!(err instanceof CiAuthError)) throw err
    // Seuls les refus sont limités par adresse : un jeton valide derrière le
    // même NAT n'est jamais bloqué par le mauvais jeton d'un voisin.
    if (!badTokenLimiter.hit(ip)) throw tooMany(event, badTokenLimiter, ip)
    throw ciAuthHttpError(err)
  }
  const key = auth.apiTokenId ?? auth.identity.label
  if (!tokenLimiter.hit(key)) throw tooMany(event, tokenLimiter, key)
  event.context.apiToken = {
    id: auth.apiTokenId ?? auth.identity.label,
    apiTokenId: auth.apiTokenId,
    projectId: auth.projectId,
    scopes: auth.scopes,
    prefix: auth.prefix,
    label: auth.identity.label,
  }
})
