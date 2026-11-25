// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 27 → § 7.2 : quand une exception approuvée change le verdict d'une
// analyse de release (réévaluation sans réanalyse), le statut
// scanoria/release-gate est republié. Le rapport signé, lui, reste celui du
// verdict d'origine (immuable) : la page Release montre les deux.

import { onVerdictChanged } from '../findings/exceptions'
import { publishReleaseGate } from './gate'

let registered = false

export function registerReleaseHooks(): void {
  if (registered) return
  onVerdictChanged(async (db, scanId) => {
    await publishReleaseGate(db, scanId)
  })
  registered = true
}
