// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// PUT /api/ai/models (admin) : force (ou rend au choix automatique, null) le
// modèle d'une tâche. Facultatif : sans réglage, le choix reste automatique.
// La découverte est relancée, puis le banc d'essai du nouveau modèle.

import { defineEventHandler } from 'h3'
import { getPool } from '../../utils/db'
import { clientAddress, readValidated, requireRole } from '../../utils/http'
import { writeAudit } from '../../utils/audit'
import { ModelsBody, requestProbe, setModelOverrides } from '../../ai/console'

export default defineEventHandler(async (event) => {
  const auth = requireRole(event, 'admin')
  const body = await readValidated(event, ModelsBody)
  const pool = getPool()
  const models = await setModelOverrides(pool, body.models, auth.user.id)
  await writeAudit(pool, {
    actor: { type: 'user', userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) },
    action: 'ai.models.update', outcome: 'success', targetType: 'ai', details: { models },
  })
  await requestProbe(pool)
  return { models }
})
