// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/imports/preview (admin) : effet d'une reprise de
// l'existant (J5) avant application : configurations du dépôt (.gitleaks.toml,
// .trivyignore, osv-scanner.toml, .semgrepignore, # nosec,
// sonar-project.properties…) et, en option, statuts de tri d'une instance
// SonarQube, Dependency-Track ou DefectDojo. Rien n'est écrit, sauf le jeton
// de l'instance, chiffré le temps de l'import (import_token).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { readValidated, requireRole } from '../../../../utils/http'
import { requireProject } from '../../../../projects/guards'
import { importPreviewSchema, runImport } from '../../../../imports/service'
import { importHttpError, repoAccess } from '../../../../imports/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, importPreviewSchema)
  try {
    const repo = body.repo ? await repoAccess(pool, project, body.ref) : null
    return await runImport(pool, {
      projectId: project.id, repo, instance: body.instance ?? null, expiresOn: body.expires_on, userId: auth.user.id, dryRun: true,
    })
  }
  catch (err) {
    importHttpError(err)
  }
})
