// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PATCH /api/projects/:id/ci/settings (admin) {autonomous_chain} : case
// « chaîne autonome » (J16), exploitée par le déploiement (chantier D).
// Enregistrée avec l'audit project.autonomous-chain ; rien d'autre ne change.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { getProjectInfo, setAutonomousChain } from '../../../../ci/integration'
import { ciSettingsSchema } from '../../../../ci/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const id = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, ciSettingsSchema)
  const pool = getPool()
  const p = await getProjectInfo(pool, id)
  if (!p) throw apiError(404, 'E_NOT_FOUND')
  await setAutonomousChain(pool, id, body.autonomous_chain, { userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) })
  return { autonomous_chain: body.autonomous_chain }
})
