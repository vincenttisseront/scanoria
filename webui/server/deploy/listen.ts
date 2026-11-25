// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 40 (0.8) : branchement du déploiement sur l'événement
// onReleaseVerdict du chantier A (server/release/events.ts, émis dans la
// console après la signature du rapport). Le registre est passé en
// paramètre : ce module ne dépend pas du fichier de A. À la fusion des deux
// chantiers, le plugin de démarrage appelle une fois
// registerDeployListeners(onReleaseVerdict).

import type pg from 'pg'
import { getPool } from '../utils/db'
import { deployPass } from './engine'
import type { VerdictEvent } from './runs'

export type VerdictRegistrar = (listener: (event: VerdictEvent) => Promise<void> | void) => unknown

let registered = false

/** Écouteur du contrat 40 : une passe immédiate pour l'analyse (refus tracé si non « passed »). */
export function deployListener(pool: () => pg.Pool = getPool) {
  return async (event: VerdictEvent): Promise<void> => {
    await deployPass(pool(), { scanId: event.scanId })
  }
}

export function registerDeployListeners(on: VerdictRegistrar, pool?: () => pg.Pool): void {
  if (registered) return
  on(deployListener(pool))
  registered = true
}
