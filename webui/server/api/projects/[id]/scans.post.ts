// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/projects/:id/scans {ref, profile?} (jeton d'API du projet, ou
// session operator) : dépose une analyse (contrat 4, enqueueScan) avec
// trigger « api » pour un jeton, « manual » pour une personne.
// → 202 {scan_id, number, url}. Une demande identique déjà en file est fusionnée.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, clientAddress, readValidated } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { enqueueScan } from '../../../scans/enqueue'
import { getProjectRef, scanCreateSchema } from '../../../gates/gates'
import { ciCaller, gateError, uuidParam, tokenLabel, tokenRowId } from '../../../gates/http'

export default defineEventHandler(async (event) => {
  const caller = ciCaller(event, 'scan:create', 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, scanCreateSchema)
  const pool = getPool()
  const project = await getProjectRef(pool, projectId)
  if (!project) throw apiError(404, 'E_NOT_FOUND')
  if (project.archived) throw gateError(409, 'E_PROJECT_ARCHIVED')
  if (body.profile) {
    const p = await pool.query('SELECT 1 FROM profiles WHERE slug = $1', [body.profile])
    if (!p.rowCount) throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'profile', code: 'unknown_profile' }] })
  }
  let res: { scanId: string, number: number, merged?: boolean }
  try {
    res = await enqueueScan(pool, {
      projectId,
      ref: body.ref,
      trigger: caller.kind === 'token' ? 'api' : 'manual',
      profileSlug: body.profile,
      requestedBy: caller.kind === 'user' ? caller.auth.user.id : undefined,
      apiTokenId: caller.kind === 'token' ? tokenRowId(caller.token) ?? undefined : undefined,
    })
  }
  catch (err) {
    // EnqueueScanError (chantier C) : code E_SCAN_* stable, jamais le message brut.
    const reason = (err as { code?: unknown }).code
    if (reason === 'E_SCAN_PROJECT_NOT_FOUND') throw apiError(404, 'E_NOT_FOUND')
    if (reason === 'E_SCAN_PROJECT_ARCHIVED') throw gateError(409, 'E_PROJECT_ARCHIVED')
    if (reason === 'E_SCAN_PROFILE' || reason === 'E_SCAN_REF') {
      throw apiError(400, 'E_VALIDATION', { issues: [{ path: reason === 'E_SCAN_REF' ? 'ref' : 'profile', code: reason }] })
    }
    if (typeof reason === 'string' && /^E_SCAN_[A-Z_]{1,40}$/.test(reason)) throw gateError(409, 'E_SCAN_REFUSED', { reason })
    throw err
  }
  await writeAudit(pool, {
    actor: caller.kind === 'user'
      ? { type: 'user', userId: caller.auth.user.id, username: caller.auth.user.username, ip: clientAddress(event) }
      : { type: 'system', username: tokenLabel(caller.token), ip: clientAddress(event) },
    action: 'scan.request', outcome: 'success', targetType: 'scan', targetId: res.scanId,
    details: { project: project.slug, ref: body.ref, profile: body.profile ?? null, number: res.number, via: caller.kind },
  })
  setResponseStatus(event, 202)
  return { scan_id: res.scanId, number: res.number, url: `/scans/${res.scanId}`, merged: res.merged ?? false }
})
