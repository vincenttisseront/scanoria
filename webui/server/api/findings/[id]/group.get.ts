// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/findings/:id/group (viewer) : groupe de résultats recoupés (F16)
// dont ce résultat fait partie : outils, indice de confiance (« confirmé par
// N outils ») et lien vers chaque résultat d'origine. null sans recoupement.

import { defineEventHandler, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError, requireRole } from '../../../utils/http'
import { uuidParam } from '../../../findings/schemas'
import { groupOf } from '../../../findings/correlation'

export default defineEventHandler(async (event) => {
  requireRole(event, 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  if (!id) throw apiError(404, 'E_NOT_FOUND')
  const pool = getPool()
  const exists = await pool.query('SELECT 1 FROM findings WHERE id = $1', [id])
  if (!exists.rowCount) throw apiError(404, 'E_NOT_FOUND')
  return { group: await groupOf(pool, id) }
})
