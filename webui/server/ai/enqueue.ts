// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 7 de la 0.3 (chantiers-0.3/README.md) : point d'entrée unique des
// tâches IA, appelé par la file d'analyses (C) et l'ingestion (D). Version
// d'attente : aucun effet tant que le chantier F n'a pas livré le connecteur.
// F remplace le corps de cette fonction en gardant sa signature.

import type { Queryable } from '../utils/db'

export interface AiTaskRequest {
  kind: string
  subjectType: 'finding' | 'scan' | 'testbed'
  subjectId: string
  projectId: string | null
  locale?: 'fr' | 'en'
  priority?: number
  requestedBy?: number | null
}

/** Dépose une tâche IA ; renvoie son id, ou null si l'IA est inactive ou le projet exclu. */
export async function enqueueAiTask(_db: Queryable, _req: AiTaskRequest): Promise<string | null> {
  return null
}
