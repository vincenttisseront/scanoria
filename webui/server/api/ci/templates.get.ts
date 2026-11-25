// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ci/templates (viewer) : liste des modèles CI officiels (J3).
// GET /api/ci/templates?file=<chemin>[&project=<id>] : contenu d'un modèle de
// la liste fermée ; avec un projet, les workflows GitHub et Forgejo sont
// rendus pour lui (adresse de la console, projet, mode, empreinte du client).

import { defineEventHandler, getQuery, setHeader } from 'h3'
import { getPool } from '../../utils/db'
import { apiError, queryValidated, requireAuth } from '../../utils/http'
import { consoleUrl } from '../../forges/context'
import { getProjectInfo } from '../../ci/integration'
import { TEMPLATE_FILES, clientSha256, readTemplate, renderWorkflow } from '../../ci/templates'
import { templateQuerySchema } from '../../ci/schemas'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  if (!Object.keys(getQuery(event)).length) {
    return { templates: TEMPLATE_FILES.map(t => ({ file: t.source, ci: t.ci, kind: t.description })), client_sha256: await clientSha256() }
  }
  const q = queryValidated(event, templateQuerySchema)
  const t = TEMPLATE_FILES.find(f => f.source === q.file)
  if (!t) throw apiError(404, 'E_NOT_FOUND')
  let body: string
  try {
    body = await readTemplate(t.source)
  }
  catch {
    throw apiError(404, 'E_NOT_FOUND')
  }
  if (q.project && t.description === 'workflow') {
    const p = await getProjectInfo(getPool(), q.project.toLowerCase())
    const url = await consoleUrl()
    if (!p) throw apiError(404, 'E_NOT_FOUND')
    if (url) {
      body = renderWorkflow(body, {
        url, projectId: p.id, mode: p.release_mode === 'pull' ? 'pull' : 'push', clientSha256: await clientSha256(), tagPatterns: p.release_patterns,
      })
    }
  }
  setHeader(event, 'content-type', 'text/plain; charset=utf-8')
  setHeader(event, 'content-disposition', `attachment; filename="${t.source.split('/').pop()}"`)
  setHeader(event, 'x-content-type-options', 'nosniff')
  return body
})
