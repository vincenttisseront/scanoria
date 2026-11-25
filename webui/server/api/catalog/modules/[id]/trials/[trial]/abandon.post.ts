// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/trials/:trial/abandon (admin) : abandonne
// l'essai (F13) ; le helper retire l'image candidate.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { apiError, requireRole } from '../../../../../../utils/http'
import { getConfig } from '../../../../../../utils/config'
import { getPool } from '../../../../../../utils/db'
import { installedModuleParam } from '../../../../../../utils/catalog-actions'
import { TrialError, abandonTrial, getTrial } from '../../../../../../vigilance/trials'
import { actorOf } from '../../../../../../vigilance/api'
import { UUID_V4_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const { id, installed } = await installedModuleParam(event)
  const trialId = getRouterParam(event, 'trial') ?? ''
  const pool = getPool()
  const trial = UUID_V4_RE.test(trialId) ? await getTrial(pool, id, trialId) : null
  if (!trial) throw apiError(404, 'E_NOT_FOUND')
  const { actor, requester } = actorOf(event, auth)
  try {
    const requestId = await abandonTrial(pool, { trial, installedVersion: installed.version, actor, requester, requestsDir: getConfig().requestsDir })
    setResponseStatus(event, 202)
    return { request_id: requestId }
  }
  catch (e) {
    if (e instanceof TrialError) throw apiError(409, 'E_PRECONDITION', { reason: e.code })
    throw e
  }
})
