// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/system/updates/history : mises à jour et retours arrière.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { requireAuth } from '../../../utils/http'

export default defineEventHandler(async (event) => {
  requireAuth(event)
  const { rows } = await getPool().query(
    `SELECT h.id::text, h.action, h.from_version, h.to_version, h.channel, h.source, h.status, h.code,
            h.request_id::text, u.username AS initiated_by,
            to_char(h.started_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS started_at,
            to_char(h.finished_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS finished_at
       FROM update_history h LEFT JOIN users u ON u.id = h.initiated_by
      ORDER BY h.started_at DESC LIMIT 50`,
  )
  return { items: rows }
})
