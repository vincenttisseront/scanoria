// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/preview (operator) : détection F1 d'un dépôt avant son
// ajout (forge connue, ou dépôt public de github.com par son URL). Lecture
// seule : rien n'est enregistré.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { readValidated, requireRole } from '../../utils/http'
import { forgeClient, getForge, openForge } from '../../forges'
import { mapProjectError, projectError } from '../../projects/errors'
import { detectWithClient, githubFullName } from '../../projects/service'
import { parseGitUrl } from '../../projects/git-url'
import { projectPreviewSchema } from '../../projects/schemas'

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const body = await readValidated(event, projectPreviewSchema)
  const pool = getPool()
  try {
    let client
    let fullName: string | null
    if ('forge_id' in body) {
      const forge = await getForge(pool, body.forge_id)
      if (!forge) throw projectError(422, 'E_FORGE_NOT_FOUND')
      client = await openForge(pool, forge)
      fullName = body.repo
    }
    else {
      parseGitUrl(body.url)
      fullName = githubFullName(body.url)
      if (!fullName) throw projectError(422, 'E_NO_FORGE_ACCESS')
      client = forgeClient({ kind: 'github', base_url: 'https://github.com' })
    }
    const repo = await client.repo(fullName)
    if (!repo.default_branch) throw projectError(422, 'E_FORGE_NOT_FOUND')
    const branches = await client.branches(repo.full_name).catch(() => [repo.default_branch!])
    return { repo, branches, detection: await detectWithClient(client, repo.full_name, repo.default_branch) }
  }
  catch (err) {
    mapProjectError(err)
  }
})
