// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/:id/webhook (J1, route publique) : webhook signé d'une
// forge. Aucune session : la signature HMAC du secret de la forge fait foi
// (server/forges/webhook.ts). La réponse part avant le traitement.

import { defineEventHandler, getRequestHeaders, getRouterParam, readRawBody, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { MAX_WEBHOOK_BYTES } from '../../../forges/signature'
import { receiveWebhook } from '../../../forges/webhook'

export default defineEventHandler(async (event) => {
  const declared = Number(event.node.req.headers['content-length'] ?? 0)
  const raw = declared > MAX_WEBHOOK_BYTES ? null : await readRawBody(event, false)
  const body = raw ? Buffer.from(raw) : (declared > MAX_WEBHOOK_BYTES ? Buffer.alloc(MAX_WEBHOOK_BYTES + 1) : null)
  const out = await receiveWebhook(getPool(), getRouterParam(event, 'id') ?? '', getRequestHeaders(event), body,
    m => console.error('[webhook]', m))
  setResponseStatus(event, out.status)
  return { code: out.code }
})
