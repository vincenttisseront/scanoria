// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/imports/apply (admin) : dépose les demandes
// d'exception de la reprise de l'existant (J5, requested_via « tool-import ») ;
// jamais d'approbation. Le jeton de l'instance est effacé. Audit project.import.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { requireProject } from '../../../../projects/guards'
import { discardImportToken, importApplySchema, runImport } from '../../../../imports/service'
import { importHttpError, repoAccess } from '../../../../imports/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const pool = getPool()
  const project = await requireProject(pool, getRouterParam(event, 'id'))
  const body = await readValidated(event, importApplySchema)
  try {
    const repo = body.repo ? await repoAccess(pool, project, body.ref) : null
    return await withTransaction(pool, async (client) => {
      const report = await runImport(client, {
        projectId: project.id, repo, instance: body.instance ?? null, importToken: body.import_token ?? null,
        expiresOn: body.expires_on, userId: auth.user.id, dryRun: false,
      })
      await writeAudit(client, {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
        action: 'project.import', outcome: 'success', targetType: 'project', targetId: project.id,
        details: {
          slug: project.slug, sources: report.sources, instance: body.instance ? { kind: body.instance.kind, base_url: body.instance.base_url, project: body.instance.project } : null,
          created: report.outcome.created.map(c => ({ id: c.id, kind: c.kind, target: c.target })).slice(0, 500),
          skipped: report.outcome.skipped.length, unsupported: report.unsupported.length,
        },
      })
      return report
    })
  }
  catch (err) {
    importHttpError(err)
  }
  finally {
    // Jeton à usage unique : effacé hors transaction, que l'application réussisse ou échoue.
    await discardImportToken(pool, body.import_token)
  }
})
