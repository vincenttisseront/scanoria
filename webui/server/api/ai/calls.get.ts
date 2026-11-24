// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/calls (operator) : journal des appels IA, métadonnées seulement
// (tâche, projet, modèle, taille envoyée, durée, issue), jamais le contenu.

import { defineEventHandler } from 'h3'
import { z } from 'zod'
import { getPool } from '../../utils/db'
import { queryValidated, requireRole } from '../../utils/http'
import { recentCalls } from '../../ai/console'

const Query = z.strictObject({ limit: z.coerce.number().int().min(1).max(500).optional() })

export default defineEventHandler(async (event) => {
  requireRole(event, 'operator')
  const q = queryValidated(event, Query)
  return { calls: await recentCalls(getPool(), q.limit ?? 100) }
})
