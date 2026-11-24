// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/ai/appliance/subjects (admin) : sujets de l'appliance qu'un
// diagnostic IA (I16) peut expliquer maintenant (alertes, dernier selftest en
// échec, mises à jour et modules en échec). Lecture seule ; vide sans
// connecteur, et la console reste alors identique.

import { defineEventHandler } from 'h3'
import { getPool } from '../../../utils/db'
import { requireRole } from '../../../utils/http'
import { diagnosableSubjects } from '../../../ai/appliance'
import { connectorEnabled } from '../../../ai/enqueue'

export default defineEventHandler(async (event) => {
  requireRole(event, 'admin')
  if (!(await connectorEnabled())) return { enabled: false, subjects: [] }
  return { enabled: true, subjects: await diagnosableSubjects(getPool()) }
})
