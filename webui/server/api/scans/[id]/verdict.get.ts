// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/scans/:id/verdict (jeton d'API du projet, ou session viewer) : état,
// verdict et raisons ordonnées (VerdictDetails), lien vers la page d'analyse,
// texte IA facultatif (ai_summary, I9). Paramètre ?locale=fr|en.
// Fichier du chantier E dans le dossier du chantier C (accord de l'intégrateur).

import { defineEventHandler, getQuery, getRouterParam } from 'h3'
import { getPool } from '../../../utils/db'
import { apiError } from '../../../utils/http'
import { ciCaller, uuidParam } from '../../../gates/http'
import { getScanVerdict } from '../../../gates/verdict'

export default defineEventHandler(async (event) => {
  const caller = ciCaller(event, 'scan:read', 'viewer')
  const id = uuidParam(getRouterParam(event, 'id'))
  const q = getQuery(event)
  const userLocale = caller.kind === 'user' ? caller.auth.user.locale : 'fr'
  const locale = q.locale === 'en' || q.locale === 'fr' ? q.locale : userLocale
  const res = await getScanVerdict(getPool(), id, locale)
  // Un jeton ne voit que les analyses de son projet : 404 sinon, sans rien révéler.
  if (!res || (caller.kind === 'token' && res.project_id !== caller.token.projectId)) throw apiError(404, 'E_NOT_FOUND')
  return res
})
