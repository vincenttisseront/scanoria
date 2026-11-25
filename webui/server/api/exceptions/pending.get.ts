// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/exceptions/pending[?project_id=…] (admin) : demandes d'exception
// en attente de décision (page « Exceptions à approuver »), avec, pour chacune,
// si l'administrateur connecté peut la décider (J15 : ni sa propre demande,
// ni un commit dont il est l'auteur).

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { deciderRefusal, listPendingExceptions } from '../../findings/exceptions'
import { UUID_RE } from '../../findings/schemas'

const query = z.strictObject({ project_id: z.string().regex(UUID_RE).optional() })

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const q = queryValidated(event, query)
  const pool = getPool()
  const me = (await pool.query<{ id: number, username: string, email: string | null, role: string, kind: string, is_active: boolean }>(
    'SELECT id::int AS id, username, email, role, kind, is_active FROM users WHERE id = $1', [auth.user.id])).rows[0]
  const items = await listPendingExceptions(pool, q.project_id)
  const ids = await pool.query<{ id: string, created_by_id: number | null }>(
    'SELECT id, created_by::int AS created_by_id FROM exceptions WHERE id = ANY($1::uuid[])', [items.map(i => i.id)])
  const createdBy = new Map(ids.rows.map(r => [r.id, r.created_by_id]))
  return {
    items: items.map(i => ({
      ...i,
      cannot_decide: me ? deciderRefusal(me, { created_by_id: createdBy.get(i.id) ?? null, requester_label: i.requester_label, commit_authors: i.commit_authors }) : 'not-admin',
    })),
  }
})
