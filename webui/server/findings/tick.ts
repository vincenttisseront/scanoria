// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tâche périodique du tri et des exceptions (0.7, B), lancée environ chaque
// heure par la boucle d'ingestion de la console :
// - avis d'échéance des exceptions approuvées (F5) ;
// - effets des règles de tri échues annulés (F4) ;
// - verdict recalculé, sans réanalyse, pour les projets dont une exception a
//   expiré la veille ou dont une règle vient d'être annulée : l'exception
//   échue redevient bloquante dans le statut publié, pas seulement à la
//   prochaine analyse. Idempotent : rien n'est écrit si le verdict ne change pas.

import type { Queryable } from '../utils/db'
import { notifyExpiringExceptions, reevaluateProject } from './exceptions'
import { expireTriageRules } from './triage-rules'

export async function triageTick(db: Queryable): Promise<{ notified: number, reverted: number, reevaluated: number }> {
  const notified = await notifyExpiringExceptions(db)
  const reverted = await expireTriageRules(db)
  const { rows } = await db.query<{ project_id: string }>(
    `SELECT DISTINCT project_id FROM exceptions
      WHERE status = 'approved' AND revoked_at IS NULL AND expires_on = current_date - 1
     UNION
     SELECT DISTINCT r.project_id FROM triage_rules r
      WHERE r.expires_on = current_date - 1 AND r.project_id IS NOT NULL
     LIMIT 200`,
  )
  let reevaluated = 0
  for (const r of rows) reevaluated += (await reevaluateProject(db, r.project_id)).length
  return { notified, reverted, reevaluated }
}
