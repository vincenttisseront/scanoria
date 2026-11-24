// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/results (J6, contrat 26 de la 0.6) : résultats
// produits ailleurs, en SARIF 2.1.0 ou CycloneDX 1.5 / 1.6 (corps JSON brut,
// 32 Mo au plus, lu en flux). Jeton d'API du projet (portée scan:create) ou
// session operator. Paramètres facultatifs : ref, commit, tool, version
// (remplacent ceux du document), category (catégorie d'un SARIF sans
// indication, sast par défaut).
// → 201 {scan_id, number, url, module, source, results, new, components, verdict}
// → 413 trop gros, 415 format inconnu, 422 document invalide {issues}.

import { createError, defineEventHandler, getHeader, getRouterParam, setResponseStatus } from 'h3'
import { z } from 'zod'
import { CATEGORIES } from '#shared/analysis'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, queryValidated } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { getProjectRef } from '../../../gates/gates'
import { ciCaller, gateError, uuidParam } from '../../../gates/http'
import { ExternalError, ingestExternal, parseJson, readBoundedBody } from '../../../external/ingest'

const query = z.strictObject({
  ref: z.string().min(1).max(255).optional(),
  commit: z.string().regex(/^[0-9a-f]{40,64}$/).optional(),
  tool: z.string().trim().min(1).max(120).optional(),
  version: z.string().trim().min(1).max(64).optional(),
  category: z.enum(CATEGORIES).optional(),
})

function externalError(err: ExternalError) {
  return createError({ statusCode: err.status, statusMessage: err.code, data: { code: err.code, issues: err.issues } })
}

export default defineEventHandler(async (event) => {
  const caller = ciCaller(event, 'scan:create', 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const q = queryValidated(event, query)
  const pool = getPool()
  const project = await getProjectRef(pool, projectId)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  if (project.archived) throw gateError(409, 'E_PROJECT_ARCHIVED')
  const declared = Number.parseInt(getHeader(event, 'content-length') ?? '', 10)
  try {
    const buf = await readBoundedBody(event.node.req, Number.isFinite(declared) ? declared : null)
    const out = await ingestExternal(pool, {
      projectId,
      doc: parseJson(buf),
      ref: q.ref ?? null,
      commit: q.commit ?? null,
      tool: q.tool ?? null,
      version: q.version ?? null,
      category: q.category ?? null,
      uploadedVia: caller.kind === 'token' ? 'api-token' : 'console',
      requestedBy: caller.kind === 'user' ? caller.auth.user.id : null,
      apiTokenId: caller.kind === 'token' ? caller.token.id : null,
    })
    await writeAudit(pool, {
      actor: caller.kind === 'user'
        ? { type: 'user', userId: caller.auth.user.id, username: caller.auth.user.username, ip: clientAddress(event) }
        : { type: 'system', username: `api-token:${caller.token.prefix}`, ip: clientAddress(event) },
      action: 'scan.external', outcome: 'success', targetType: 'scan', targetId: out.scanId,
      details: { project: project.slug, number: out.number, module: out.moduleId, ...out.source, results: out.count, verdict: out.verdict },
    })
    setResponseStatus(event, 201)
    return {
      scan_id: out.scanId, number: out.number, url: `/scans/${out.scanId}`, module: out.moduleId, source: out.source,
      results: out.count, new: out.newCount, components: out.components, verdict: out.verdict,
    }
  }
  catch (err) {
    if (err instanceof ExternalError) {
      await writeAudit(pool, {
        actor: caller.kind === 'user'
          ? { type: 'user', userId: caller.auth.user.id, username: caller.auth.user.username, ip: clientAddress(event) }
          : { type: 'system', username: `api-token:${caller.token.prefix}`, ip: clientAddress(event) },
        action: 'scan.external', outcome: 'failure', targetType: 'project', targetId: projectId,
        details: { project: project.slug, code: err.code, issues: err.issues.length },
      }).catch(() => {})
      if (err.code === 'E_EXTERNAL_REF' && err.status === 404) throw apiError(404, 'E_NOT_FOUND')
      throw externalError(err)
    }
    throw err
  }
})
