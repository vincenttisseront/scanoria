// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/ci/pr (operator) : ouvre la PR d'intégration (J2)
// maintenant, ou de nouveau si la précédente a été fermée ou a échoué. Une
// seule demande active par projet ; l'appliance ne fusionne jamais la PR.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, requireRole } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { proposeIntegration } from '../../../../ci/integration'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  const res = await proposeIntegration(getPool(), id, {
    force: true, actor: { userId: auth.user.id, username: auth.user.username }, locale: auth.user.locale === 'en' ? 'en' : 'fr',
  })
  if (res.outcome === 'not-applicable') throw apiError(404, 'E_NOT_FOUND')
  return res
})
