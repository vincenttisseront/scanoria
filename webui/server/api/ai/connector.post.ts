// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/connector (admin) : active ou modifie le connecteur Ollama.
// Une seule saisie obligatoire (l'adresse) et une seule confirmation (modale
// d'activation, confirmed: true). Le jeton éventuel est chiffré en base
// (contrat 2, clé dédiée ai-token.key) et n'entre jamais dans la demande au helper, qui résout,
// épingle et ouvre la sortie pour scanoria-ai seulement (set-ai-endpoint).

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, readValidated, requireRole } from '../../utils/http'
import { submitHelperAction } from '../../utils/helper-actions'
import { ConnectorBody, saveSetting } from '../../ai/console'
import { loadAiSettings } from '../../ai/config'
import { deleteToken, saveToken } from '../../ai/token'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, ConnectorBody)
  const pool = getPool()
  const previous = (await loadAiSettings(pool)).tokenCredentialId
  const stored = previous !== null
  const hasToken = typeof body.token === 'string' || (body.token === undefined && stored)
  if (hasToken && body.url.startsWith('http:')) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'url', code: 'token_requires_https' }] })
  const params = {
    enabled: true as const,
    url: body.url,
    ...(body.allow_insecure ? { allow_insecure: true } : {}),
    ...(hasToken ? { token: true } : {}),
    ...(body.ca_pem ? { ca_pem: body.ca_pem } : {}),
    ...(body.skip_tls_verify ? { skip_tls_verify: true } : {}),
  }
  // Un nouveau jeton est scellé AVANT le dépôt : la clé dédiée existe quand le
  // helper la copie pour scanoria-ai. Si le dépôt est refusé, il est retiré.
  const fresh = typeof body.token === 'string' ? await saveToken(pool, body.token, auth.user.id) : null
  let submitted
  try {
    submitted = await submitHelperAction(event, 'set-ai-endpoint', params, {
      auditDetails: { url: body.url, token: hasToken, ca: Boolean(body.ca_pem), tls_verify: !body.skip_tls_verify, confirmed: true },
    })
  }
  catch (err) {
    await deleteToken(pool, fresh)
    throw err
  }
  if (fresh) {
    await saveSetting(pool, 'ai.token_credential_id', fresh, auth.user.id)
    await deleteToken(pool, previous)
  }
  else if (body.token === null) {
    await saveSetting(pool, 'ai.token_credential_id', null, auth.user.id)
    await deleteToken(pool, previous)
  }
  return submitted
})
