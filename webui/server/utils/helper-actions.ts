// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Dépôt d'une demande au service root au nom de l'utilisateur connecté :
// contrôle du rôle (admin), validation, écriture atomique, audit.

import { setResponseStatus, type H3Event } from 'h3'
import { getConfig } from './config'
import { getPool } from './db'
import { writeAudit } from './audit'
import { sanitizeParams, submitRequest } from './requests'
import { clientAddress, mapRequestError, requireRole } from './http'
import type { RequestType } from '#shared/schemas'

export interface SubmitOptions {
  /** Contexte ajouté à la ligne helper_requests (jamais au fichier de demande). */
  dbContext?: Record<string, unknown>
  /** Détails supplémentaires pour le journal d'audit (sans secret). */
  auditDetails?: Record<string, unknown>
}

export async function submitHelperAction(event: H3Event, type: RequestType, params: unknown, opts: SubmitOptions = {}) {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const address = clientAddress(event)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: address }
  let submitted
  try {
    submitted = await submitRequest(
      pool,
      getConfig().requestsDir,
      type,
      params,
      { userId: auth.user.id, username: auth.user.username, address },
      new Date(),
      opts.dbContext,
    )
  }
  catch (err) {
    await writeAudit(pool, {
      actor, action: `system.${type}.request`, outcome: 'failure', targetType: 'helper-request',
      details: { error: (err as Error).name },
    }).catch(() => {})
    mapRequestError(err)
  }
  await writeAudit(pool, {
    actor,
    action: `system.${type}.request`,
    outcome: 'success',
    targetType: 'helper-request',
    targetId: submitted.id,
    requestId: submitted.id,
    details: {
      params: sanitizeParams(type, (params ?? {}) as Record<string, unknown>),
      ...opts.auditDetails,
    },
  })
  setResponseStatus(event, 202)
  return { request_id: submitted.id, type, status: 'pending' as const, created_at: submitted.createdAt }
}
