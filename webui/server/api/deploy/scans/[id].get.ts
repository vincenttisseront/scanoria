// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/deploy/scans/:id (lecture) : attestations et déploiements d'une
// analyse, pour la page Release (rattachement à l'analyse, J11).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { listAttestations } from '../../../attest'
import { listDeployments } from '../../../deploy/runs'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = getRouterParam(event, 'id') ?? ''
  if (!/^[0-9a-f-]{36}$/.test(id)) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const attestations = (await listAttestations(pool, id)).map(({ envelope, ...a }) => ({ ...a, downloadable: !!envelope }))
  return { attestations, deployments: await listDeployments(pool, { scanId: id }) }
})
