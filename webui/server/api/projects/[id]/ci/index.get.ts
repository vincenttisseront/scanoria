// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/projects/:id/ci (viewer) : intégration CI du projet (0.8, C) :
// mode de release, case « chaîne autonome » (J16), CI détectée et modèle
// retenu (J3), PR d'intégration et protection proposée (J2), liaisons OIDC
// (J4), adresse de la console et empreinte du client scanoria-scan.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../../utils/db'
import { apiError, requireAuth } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { getForge } from '../../../../forges'
import { consoleUrl } from '../../../../forges/context'
import { chooseCi, getProjectInfo, listIntegrationRequests, proposedContexts } from '../../../../ci/integration'
import { listBindings, listIssuers } from '../../../../ci/oidc'
import { clientSha256 } from '../../../../ci/templates'

export default defineEventHandler(async (event) => {
  const auth = requireAuth(event)
  const id = uuidParam(getRouterParam(event, 'id'))
  const pool = getPool()
  const p = await getProjectInfo(pool, id)
  if (!p) throw apiError(404, 'E_NOT_FOUND')
  const forge = p.forge_id ? await getForge(pool, p.forge_id) : null
  const detection = p.detection && !('error' in p.detection) ? p.detection : null
  const isAdmin = auth.user.role === 'admin'
  return {
    project_id: p.id,
    release_mode: p.release_mode,
    release_patterns: p.release_patterns,
    autonomous_chain: p.autonomous_chain,
    forge: forge ? { id: forge.id, kind: forge.kind, name: forge.name } : null,
    repository: p.repo_full_name,
    default_branch: p.default_branch,
    detected_ci: detection?.ci ?? null,
    template: forge && detection ? chooseCi(forge.kind, Array.isArray(detection.ci) ? detection.ci : []).ci : null,
    contexts: { pr: proposedContexts(p, false)[0], release_gate: proposedContexts(p, true)[1] },
    requests: await listIntegrationRequests(pool, id),
    bindings: await listBindings(pool, id),
    // Émetteurs disponibles pour une liaison (administrateur seulement).
    issuers: isAdmin ? (await listIssuers(pool)).map(i => ({ id: i.id, kind: i.kind, issuer: i.issuer, enabled: i.enabled })) : [],
    console_url: await consoleUrl(),
    client_sha256: await clientSha256(),
  }
})
