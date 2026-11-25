// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 27 → contrat 30 : quand une exception approuvée change le verdict
// d'une analyse (réévaluation du chantier B, sans réanalyse), le statut de
// commit et le commentaire de PR sont republiés.

import { onVerdictChanged } from '../findings/exceptions'
import { publishScan } from './publish'

let registered = false

export function registerForgeVerdictHook(): boolean {
  if (registered) return true
  onVerdictChanged(async (db, scanId) => {
    await publishScan(db, scanId, { phase: 'final' })
  })
  registered = true
  return true
}
