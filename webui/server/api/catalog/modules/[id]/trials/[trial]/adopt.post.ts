// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/catalog/modules/:id/trials/:trial/adopt (admin) : adopte la version
// essayée (F13). C'est une mise à jour normale (update-module) : sauvegarde,
// santé, banc d'essai et retour arrière du helper ; mêmes contrôles que
// POST /api/catalog/modules/:id/update.

import { defineEventHandler, getRouterParam } from 'h3'
import { apiError, requireRole } from '../../../../../../utils/http'
import { getPool } from '../../../../../../utils/db'
import { installedModuleParam } from '../../../../../../utils/catalog-actions'
import { submitHelperAction } from '../../../../../../utils/helper-actions'
import { compareVersions, findModule } from '../../../../../../utils/catalog'
import { buildInstallPlan } from '../../../../../../utils/module-plan'
import { getTrial, markAdopted } from '../../../../../../vigilance/trials'
import { UUID_V4_RE } from '#shared/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  const { id, installed, ctx } = await installedModuleParam(event)
  const trialId = getRouterParam(event, 'trial') ?? ''
  const pool = getPool()
  const trial = UUID_V4_RE.test(trialId) ? await getTrial(pool, id, trialId) : null
  if (!trial) throw apiError(404, 'E_NOT_FOUND')
  if (trial.status !== 'done') throw apiError(409, 'E_PRECONDITION', { reason: 'E_TRIAL_STATE' })
  const target = findModule(ctx.index, id, trial.to_version)
  if (!target || target.image?.split('@')[1] !== trial.to_digest) throw apiError(404, 'E_NOT_FOUND')
  if (compareVersions(target.version, installed.version) <= 0) throw apiError(409, 'E_NO_UPDATE')
  const plan = buildInstallPlan(
    [{ id, version: target.version, options: installed.options }],
    { ...ctx, installed: ctx.installed.filter(m => m.id !== id), acceptLicenses: [] },
  )
  const blockers = [
    ...plan.blockers,
    ...plan.items.filter(i => i.id !== id).map(i => ({ code: 'E_DEPENDENCY' as const, module: id, other: i.id })),
  ]
  if (blockers.length) throw apiError(409, 'E_PLAN', { blockers })
  const res = await submitHelperAction(event, 'update-module', { id, version: target.version }, {
    auditDetails: { from_version: installed.version, trial_id: trial.id },
  })
  await markAdopted(pool, trial.id)
  return { ...res, trial_id: trial.id }
})
