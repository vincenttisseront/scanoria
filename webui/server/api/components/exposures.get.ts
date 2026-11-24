// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/components/exposures (viewer) : projets nouvellement touchés par
// une re-corrélation (contrat 16) depuis 7 jours ; bandeau du tableau de bord.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { requireRole } from '../../utils/http'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const r = await getPool().query<{ project_id: string, slug: string, name: string, at: string, details: Record<string, unknown> }>(
    `SELECT DISTINCT ON (a.target_id) a.target_id AS project_id, p.slug, p.name,
            to_char(a.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS at, a.details
       FROM audit_log a JOIN projects p ON p.id::text = a.target_id
      WHERE a.action = 'recorrelation.exposure' AND a.occurred_at > now() - interval '7 days'
        AND ($1::boolean OR p.archived_at IS NULL)
      ORDER BY a.target_id, a.occurred_at DESC
      LIMIT 200`, [auth.user.role === 'admin'])
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
  return {
    items: r.rows
      .map(x => ({
        project: { id: x.project_id, slug: x.slug, name: x.name },
        at: x.at,
        scan_id: typeof x.details.scan_id === 'string' ? x.details.scan_id : null,
        count: num(x.details.count), malicious: num(x.details.malicious), kev: num(x.details.kev),
        critical: num(x.details.critical), high: num(x.details.high),
      }))
      .sort((a, b) => b.malicious - a.malicious || b.at.localeCompare(a.at)),
  }
})
