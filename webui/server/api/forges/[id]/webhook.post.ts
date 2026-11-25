// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/:id/webhook (J1, route publique) : webhook signé d'une
// forge. Aucune session : la signature HMAC du secret de la forge fait foi
// (server/forges/webhook.ts). La réponse part avant le traitement. Le corps
// est lu en flux et coupé à MAX_WEBHOOK_BYTES, déclaré ou non (envoi
// « chunked » compris) : rien de plus n'est gardé en mémoire.

import { defineEventHandler, getRequestHeaders, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { MAX_WEBHOOK_BYTES } from '../../../forges/signature'
import { readBounded, receiveWebhook } from '../../../forges/webhook'

export default defineEventHandler(async (event) => {
  const read = await readBounded(event.node.req, MAX_WEBHOOK_BYTES).catch(() => 'too-large' as const)
  const out = await receiveWebhook(getPool(), getRouterParam(event, 'id') ?? '', getRequestHeaders(event), read === 'too-large' ? null : read,
    m => console.error('[webhook]', m))
  setResponseStatus(event, out.status)
  return { code: out.code }
})
