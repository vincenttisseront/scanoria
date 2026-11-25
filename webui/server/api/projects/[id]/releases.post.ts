// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/releases {tag, commit?} (§ 7.2, mode poussé) : la CI
// demande l'analyse de release d'un tag (scanoria-scan --profile release
// --ref <tag>). Jeton d'API du projet (portée scan:create) ou opérateur ;
// contrat 41 (authenticateCi, chantier C) quand il sera fusionné.
// - Le commit du tag est lu dans la forge quand le projet y a accès (le
//   commit envoyé doit alors correspondre) ; sinon commit est obligatoire.
// - Une release n'est jamais analysée deux fois : le même tag rend l'analyse
//   existante (200) ; un tag déplacé est refusé (409) et signalé dans l'audit.
// - Forge reliée mais en erreur : 503 E_RELEASE_FORGE, rien n'est enregistré.
// → 202 {scan_id, number, url, release_url, existing: false}.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { ciCaller, gateError, uuidParam } from '../../../gates/http'
import { getProjectRef } from '../../../gates/gates'
import { enqueueRelease, reportMovedTag } from '../../../release/poll'
import { releaseError, tagCommit } from '../../../release/api'
import { isSafeTag } from '../../../forges/release'

const Body = z.strictObject({
  tag: z.string().min(1).max(255).refine(isSafeTag, 'invalid_tag'),
  commit: z.string().regex(/^[0-9a-f]{40,64}$/).optional(),
})

export default defineEventHandler(async (event) => {
  const caller = ciCaller(event, 'scan:create', 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, Body)
  const pool = getPool()
  const project = await getProjectRef(pool, projectId)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  if (project.archived) throw gateError(409, 'E_PROJECT_ARCHIVED')
  const mode = (await pool.query<{ release_mode: string }>('SELECT release_mode FROM projects WHERE id = $1', [projectId])).rows[0]?.release_mode
  if (mode === 'off') throw releaseError(409, 'E_RELEASE_MODE')

  const known = (await pool.query<{ commit_sha: string, scan_id: string | null, number: number | null }>(
    `SELECT rc.commit_sha, rc.scan_id::text, s.number FROM release_candidates rc LEFT JOIN scans s ON s.id = rc.scan_id
      WHERE rc.project_id = $1 AND rc.tag = $2`, [projectId, body.tag])).rows[0]

  // Projet relié à une forge : son commit fait foi. Forge en erreur : 503,
  // jamais le commit fourni par la CI à sa place.
  let commit: string | null | 'absent'
  try {
    commit = await tagCommit(pool, projectId, body.tag)
  }
  catch {
    throw releaseError(503, 'E_RELEASE_FORGE')
  }
  if (commit === 'absent') throw releaseError(404, 'E_RELEASE_TAG')
  if (commit && body.commit && commit !== body.commit) throw releaseError(409, 'E_RELEASE_COMMIT')
  const sha = commit ?? body.commit ?? null
  if (!sha) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'commit', code: 'required_without_forge' }] })

  if (known) {
    if (known.commit_sha !== sha) {
      await reportMovedTag(pool, projectId, body.tag, known.commit_sha, sha)
      throw releaseError(409, 'E_RELEASE_TAG_MOVED')
    }
    if (known.scan_id) return { scan_id: known.scan_id, number: known.number, url: `/scans/${known.scan_id}`, release_url: `/releases/${known.scan_id}`, existing: true }
  }
  const res = await enqueueRelease(pool, projectId, body.tag, sha, 'push', caller.kind === 'token' ? { apiTokenId: caller.token.id } : { requestedBy: caller.auth.user.id })
  if (!res) throw releaseError(409, 'E_RELEASE_TAG_MOVED')
  if (res.existing) return { scan_id: res.scanId, number: res.number, url: `/scans/${res.scanId}`, release_url: `/releases/${res.scanId}`, existing: true }
  await writeAudit(pool, {
    actor: caller.kind === 'user'
      ? { type: 'user', userId: caller.auth.user.id, username: caller.auth.user.username, ip: clientAddress(event) }
      : { type: 'system', username: `api-token:${caller.token.prefix}`, ip: clientAddress(event) },
    action: 'release.request', outcome: 'success', targetType: 'scan', targetId: res.scanId,
    details: { project: project.slug, tag: body.tag, commit: sha, via: caller.kind },
  })
  setResponseStatus(event, 202)
  return { scan_id: res.scanId, number: res.number, url: `/scans/${res.scanId}`, release_url: `/releases/${res.scanId}`, existing: false }
})
