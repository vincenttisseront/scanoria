// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/vex/projects/:id/import (operator) : H7, import d'un document
// OpenVEX 0.2 ou CycloneDX VEX, lu strictement. dry_run (défaut) : aperçu des
// effets, rien n'est écrit. Sinon, dans une transaction : chaque déclaration
// not_affected ou fixed devient une DEMANDE d'exception (requested_via
// « tool-import »), jamais une approbation ; les autres statuts sont gardés
// pour information. Aucune demande pour un avis MAL- (H4) ni contre un verrou
// (G8). Audité (vex.import).

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool, withTransaction } from '../../../../utils/db'
import { apiError, clientAddress, readValidated, requireRole } from '../../../../utils/http'
import { writeAudit } from '../../../../utils/audit'
import { uuidParam } from '../../../../gates/http'
import { importVex, VexError, vexImportSchema } from '../../../../vex/vex'
import { VexFormatError } from '../../../../vex/format'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'operator')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const body = await readValidated(event, vexImportSchema)
  const actor = { userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) ?? null }
  try {
    return await withTransaction(getPool(), db => importVex(db, projectId, body.document, { dryRun: body.dry_run, actor, expiresOn: body.expires_on }))
  }
  catch (err) {
    if (err instanceof VexFormatError) {
      await writeAudit(getPool(), {
        actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: actor.ip },
        action: 'vex.import', outcome: 'failure', targetType: 'project', targetId: projectId,
        details: { code: err.code, field: err.detail },
      })
      throw apiError(400, 'E_VALIDATION', { reason: err.code, field: err.detail })
    }
    if (err instanceof VexError) throw apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code, { field: err.detail })
    throw err
  }
})
