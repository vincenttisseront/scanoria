// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/trials (admin) : essaie une version plus
// récente du module (F13) sur ses dernières analyses, sans effet de bord.

import { defineEventHandler, setResponseStatus } from 'h3'
import { apiError, readValidated, requireRole } from '../../../../../utils/http'
import { getConfig } from '../../../../../utils/config'
import { getPool } from '../../../../../utils/db'
import { installedModuleParam } from '../../../../../utils/catalog-actions'
import { TrialError, startTrial } from '../../../../../vigilance/trials'
import { actorOf, trialBodySchema } from '../../../../../vigilance/api'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const { id, ctx } = await installedModuleParam(event)
  const body = await readValidated(event, trialBodySchema)
  const { actor, requester } = actorOf(event, auth)
  try {
    const r = await startTrial(getPool(), {
      moduleId: id, version: body.version ?? null, sampleSize: body.sample_size, actor, requester,
      requestsDir: getConfig().requestsDir, installed: ctx.installed, index: ctx.index,
    })
    setResponseStatus(event, 202)
    return { trial_id: r.trialId, request_id: r.requestId, version: r.version }
  }
  catch (e) {
    if (e instanceof TrialError) throw apiError(409, 'E_PRECONDITION', { reason: e.code })
    throw e
  }
})
