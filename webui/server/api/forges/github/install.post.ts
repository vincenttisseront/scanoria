// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/github/install (admin, J1) : retour de GitHub après
// l'installation de l'application (setup_url). L'identifiant d'installation
// vient de l'adresse : il n'est retenu que si GitHub confirme qu'il
// appartient à l'application de cette forge. La découverte démarre aussitôt.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { clientAddress, readValidated, requireRole } from '../../../utils/http'
import { addInstallation, refreshAppCredential, verifyInstallation } from '../../../forges/apps'
import { getForge } from '../../../forges'
import { getPool } from '../../../utils/db'
import { startDiscovery } from '../../../projects/forges'
import { mapProjectError, projectError } from '../../../projects/errors'

const schema = z.strictObject({
  forge_id: z.uuid(),
  installation_id: z.string().regex(/^\d{1,20}$/),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, schema)
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const pool = getPool()
  const forge = await getForge(pool, body.forge_id)
  if (!forge || forge.kind !== 'github') throw projectError(404, 'E_FORGEAPP_KIND')
  try {
    if (!(await verifyInstallation(pool, forge, body.installation_id))) throw projectError(400, 'E_FORGEAPP_INSTALLATION')
    const added = await addInstallation(pool, forge.id, body.installation_id, actor)
    await refreshAppCredential(pool, (await getForge(pool, forge.id))!)
    startDiscovery(pool, forge.id, actor)
    return { forge_id: forge.id, added }
  }
  catch (err) {
    mapProjectError(err)
  }
})
