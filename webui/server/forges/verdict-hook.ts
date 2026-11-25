// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 27 → contrat 30 : quand une exception approuvée change le verdict
// d'une analyse (reevaluateProject du chantier B, sans réanalyse), le statut
// de commit et le commentaire de PR sont republiés. L'écouteur est inscrit
// dès que B expose onVerdictChanged (server/findings/exceptions.ts) ; avant,
// rien n'est inscrit et rien ne change.

import type pg from 'pg'
import * as exceptions from '../findings/exceptions'
import { publishScan } from './publish'

type Listener = (db: pg.Pool, scanId: string) => Promise<void>
let registered = false

export function registerForgeVerdictHook(): boolean {
  if (registered) return true
  const on = (exceptions as unknown as { onVerdictChanged?: (l: Listener) => void }).onVerdictChanged
  if (typeof on !== 'function') return false
  on(async (db, scanId) => {
    await publishScan(db, scanId, { phase: 'final' })
  })
  registered = true
  return true
}
