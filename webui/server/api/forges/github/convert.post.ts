// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/github/convert (admin, J1) : retour de GitHub après la
// création de l'application. Le jeton d'état (signé, lié à l'administrateur,
// 30 minutes) est vérifié, le code échangé contre la clé de l'application,
// puis la forge est enregistrée. Rend l'adresse d'installation.

import { defineEventHandler, setResponseStatus } from 'h3'
import { z } from 'zod'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { convertManifest, installUrl, saveGithubApp, verifyManifestState } from '../../../forges/apps'
import { getForge } from '../../../forges'
import { getPool } from '../../../utils/db'
import { writeAudit } from '../../../utils/audit'
import { mapProjectError, projectError } from '../../../projects/errors'

const schema = z.strictObject({
  code: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
  state: z.string().min(10).max(4000),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, schema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const pool = getPool()
  const state = await verifyManifestState(body.state, auth.user.id)
  if (!state) {
    await writeAudit(pool, { actor, action: 'forge.app-create', outcome: 'failure', targetType: 'forge', details: { reason: 'state' } })
    throw projectError(400, 'E_FORGEAPP_STATE')
  }
  // Un code déjà échangé : la forge existe, on renvoie simplement l'installation.
  if (await getForge(pool, state.forge_id)) throw projectError(409, 'E_FORGEAPP_STATE')
  try {
    const conv = await convertManifest(state.base_url, body.code)
    const forgeId = await saveGithubApp(pool, state, conv, actor)
    setResponseStatus(event, 201)
    return { forge_id: forgeId, slug: conv.slug, install_url: installUrl(state.base_url, conv.slug) }
  }
  catch (err) {
    mapProjectError(err)
  }
})
