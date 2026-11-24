// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/group-status (operator) : tri d'un groupe de
// résultats recoupés (F16). Le statut s'applique à chaque résultat du groupe
// (hors corrigés), avec une ligne d'audit par résultat, dans une seule
// transaction. Mêmes règles que le tri d'un résultat : motif et date de fin
// pour une acceptation, et aucun paquet malveillant (H4) accepté ni classé
// faux positif : le groupe entier est alors refusé.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { setFindingStatus, TriageError } from '../../../findings/triage'
import { isoDay, MAX_EXCEPTION_DAYS } from '../../../findings/exceptions'
import { statusChangeSchema, uuidParam } from '../../../findings/schemas'
import { groupOf } from '../../../findings/correlation'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const body = await readValidated(event, statusChangeSchema)
  if (body.status === 'accepted' && (body.until < isoDay() || body.until > isoDay(MAX_EXCEPTION_DAYS))) {
    throw apiError(400, 'E_VALIDATION', { issues: [{ path: 'until', code: 'out_of_range' }] })
  }
  const pool = getPool()
  const actor = { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
  const until = body.status === 'accepted' ? body.until : null
  try {
    return await withTransaction(pool, async (db) => {
      const group = await groupOf(db, id)
      const ids = group ? [...new Set([id, ...group.members.map(m => m.id)])] : [id]
      for (const fid of ids) {
        const { before } = await setFindingStatus(db, fid, { status: body.status, reason: body.reason ?? null, until }, auth.user.id)
        await writeAudit(db, {
          actor, action: 'finding.status', outcome: 'success', targetType: 'finding', targetId: fid,
          details: { project_id: before.project_id, from: before.status, to: body.status, reason: body.reason ?? null, until, group_of: id, group_key: group?.key ?? null },
        })
      }
      return { updated: ids }
    })
  }
  catch (err) {
    if (err instanceof TriageError) {
      if (err.code === 'E_MALICIOUS') {
        await writeAudit(pool, { actor, action: 'finding.status', outcome: 'denied', targetType: 'finding', targetId: id, details: { to: body.status, reason_code: 'malicious', group: true } })
        throw apiError(409, 'E_MALICIOUS')
      }
      throw apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code === 'E_NOT_FOUND' ? 'E_NOT_FOUND' : 'E_VALIDATION')
    }
    throw err
  }
})
