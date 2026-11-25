// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/vex/projects/:id/statements?scan_id= (viewer) : H7, déclarations VEX
// en vigueur du projet (tirées des exceptions approuvées et importées), pour
// la page du projet, avec l'empreinte du document OpenVEX canonique.

import { defineEventHandler, getRouterParam } from 'h3'
import { z } from 'zod'
import { getPool } from '../../../../utils/db'
import { apiError, queryValidated, requireRole } from '../../../../utils/http'
import { uuidParam } from '../../../../gates/http'
import { buildVex, VexError } from '../../../../vex/vex'

const Query = z.strictObject({ scan_id: z.string().uuid().optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const projectId = uuidParam(getRouterParam(event, 'id'))
  const q = queryValidated(event, Query)
  try {
    const built = await buildVex(getPool(), projectId, { scanId: q.scan_id ?? null })
    return { sha256: built.sha256, statements: built.statements }
  }
  catch (err) {
    if (err instanceof VexError) throw apiError(err.code === 'E_NOT_FOUND' ? 404 : 400, err.code)
    throw err
  }
})
