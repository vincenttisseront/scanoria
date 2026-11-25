// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/findings/:id/group-status (operator) : tri d'un groupe de
// résultats recoupés (F16). Le statut s'applique à chaque résultat du groupe
// (hors corrigés), avec une ligne d'audit par résultat, dans une seule
// transaction. Mêmes règles que le tri d'un résultat : « accepted » dépose une
// demande d'exception par résultat (F5, J15 ; réponse 202 { requested }), un
// faux positif est refusé à l'auteur du commit et aux comptes non humains, et
// aucun paquet malveillant (H4) n'est accepté ni classé faux positif : le
// groupe entier est alors refusé.

import { defineEventHandler, getRouterParam, setResponseStatus } from 'h3'
import { getPool, withTransaction } from '../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../utils/http'
import { writeAudit } from '../../../utils/audit'
import { setFindingStatus } from '../../../findings/triage'
import { isoDay, MAX_EXCEPTION_DAYS, requestFindingAcceptance } from '../../../findings/exceptions'
import { triageHttpError } from '../../../findings/triage-http'
import { statusChangeSchema, uuidParam } from '../../../findings/schemas'
import { byCodePoint, groupMemberIds, groupOf } from '../../../findings/correlation'

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
  try {
    return await withTransaction(pool, async (db) => {
      const group = await groupOf(db, id)
      // Tous les membres (sans le plafond d'affichage), verrouillés dans l'ordre des id :
      // deux tris simultanés du même groupe ne s'interbloquent pas.
      const ids = [...new Set([id, ...(await groupMemberIds(db, id) ?? [])])].sort(byCodePoint)
      if (body.status === 'accepted') {
        const requested: string[] = []
        for (const fid of ids) {
          const { request } = await requestFindingAcceptance(db, fid, auth.user, { reason: body.reason, until: body.until })
          requested.push(request.id)
        }
        setResponseStatus(event, 202)
        return { updated: [], requested }
      }
      for (const fid of ids) {
        const { before } = await setFindingStatus(db, fid, { status: body.status, reason: body.reason ?? null }, auth.user.id)
        await writeAudit(db, {
          actor, action: 'finding.status', outcome: 'success', targetType: 'finding', targetId: fid,
          details: { project_id: before.project_id, from: before.status, to: body.status, reason: body.reason ?? null, group_of: id, group_key: group?.key ?? null },
        })
      }
      return { updated: ids, requested: [] }
    })
  }
  catch (err) {
    throw await triageHttpError(err, pool, actor, id, { to: body.status, group: true })
  }
})
