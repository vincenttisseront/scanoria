// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// POST /api/ai/search (viewer) : traduction d'une phrase en filtres de la
// console (I8). Seules la phrase, masquée, et les valeurs de filtres permises
// sont envoyées à l'IA. Sans connecteur : subject_id null, la recherche
// classique reste disponible.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getPool } from '../../utils/db'
import { readValidated, requireRole } from '../../utils/http'
import { requestSearch, SearchBody } from '../../ai/search'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'viewer')
  const body = await readValidated(event, SearchBody)
  const r = await requestSearch(getPool(), body, auth.user.id, auth.user.locale)
  setResponseStatus(event, r.task_id ? 202 : 200)
  return r
})
