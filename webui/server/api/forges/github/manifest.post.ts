// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/forges/github/manifest (admin, J1) : prépare la création de
// l'application GitHub en un clic. Rend le manifeste et l'adresse où la
// console le poste ; GitHub revient ensuite sur la page /forges/github.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { readValidated, requireRole } from '../../../utils/http'
import { startGithubManifest } from '../../../forges/apps'
import { consoleUrl } from '../../../forges/context'
import { mapProjectError, projectError } from '../../../projects/errors'

const schema = z.strictObject({
  base_url: z.string().min(9).max(512).default('https://api.github.com'),
  org: z.string().trim().min(1).max(39).nullable().optional(),
  name: z.string().trim().min(1).max(100),
  /** La forge peut joindre l'appliance (webhooks) ; sinon mode tiré. */
  reachable: z.boolean().default(false),
})

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, schema)
  const url = await consoleUrl()
  if (!url) throw projectError(409, 'E_FORGEAPP_CONSOLE_URL')
  try {
    const m = await startGithubManifest({ base_url: body.base_url, org: body.org ?? null, name: body.name, consoleUrl: url, userId: auth.user.id, reachable: body.reachable })
    return { action: m.action, manifest: JSON.stringify(m.manifest) }
  }
  catch (err) {
    mapProjectError(err)
  }
})
