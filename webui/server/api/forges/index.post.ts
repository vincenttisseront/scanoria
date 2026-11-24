// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges (admin) : ajoute une forge (Forgejo, GitHub ; GitLab pas
// encore pris en charge). L'accès est vérifié immédiatement ; avec un jeton,
// la découverte des dépôts démarre aussitôt (principe 8).

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../utils/http'
import { createForge, startDiscovery } from '../../projects/forges'
import { forgeCreateSchema } from '../../projects/schemas'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, forgeCreateSchema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const pool = getPool()
  const { forge, login } = await createForge(pool, body, actor)
  if (forge.discovery && forge.has_token) startDiscovery(pool, forge.id, actor)
  setResponseStatus(event, 201)
  return { forge, login, discovery_started: forge.discovery && forge.has_token }
})
