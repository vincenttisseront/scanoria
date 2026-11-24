// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/requests/:id : suivi d'une demande (étape courante lue dans l'état
// publié). Une passe d'ingestion est lancée pour un retour rapide.

import { defineEventHandler, getRouterParam } from 'h3'
import { getConfig } from '../../utils/config'
import { getPool } from '../../utils/db'
import { apiError, requireAuth } from '../../utils/http'
import { getHelperRequest } from '../../utils/requests'
import { ingestNow } from '../../utils/runtime'
import { readPublishedState } from '../../utils/appliance'
import { readModulesState } from '../../utils/catalog'
import { UUID_V4_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  const id = getRouterParam(event, 'id') ?? ''
  if (!UUID_V4_RE.test(id)) throw apiError(404, 'E_NOT_FOUND')
  await ingestNow()
  const row = await getHelperRequest(getPool(), id)
  if (!row) throw apiError(404, 'E_NOT_FOUND')
  if (auth.user.role === 'viewer' && row.requested_by !== String(auth.user.id)) throw apiError(403, 'E_FORBIDDEN')
  let step: string | null = null
  let progress: number | null = null
  if (row.status === 'pending' || row.status === 'running') {
    const published = await readPublishedState(getConfig().stateFile)
    const current = (published.state?.helper as { current?: { id?: string, step?: string } | null } | undefined)?.current
    if (current?.id === id && typeof current.step === 'string') step = current.step
    // Opérations sur les modules : étape et avancement publiés dans modules/state.json.
    const op = (await readModulesState(getConfig().modulesStateFile)).operations.find(o => o.request_id === id && !o.finished_at)
    if (op) {
      step = op.step ?? step
      progress = op.progress ?? null
    }
  }
  return { ...row, step, progress }
})
