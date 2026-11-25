// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrat 40 : après le verdict d'une analyse de release (une fois le rapport
// signé) ou d'une branche configurée (deploy_targets.on_trigger = 'branch',
// sans rapport : reportSha256 null), les écouteurs sont appelés une seule
// fois par analyse, depuis la boucle de la console (releaseTick). Le chantier D
// y branche J9, J11, J12 et J13. Un écouteur n'agit jamais si
// verdict !== 'passed' : il trace un refus (deployments.status = 'refused').
// Un écouteur qui lève n'empêche pas les autres ; l'émission est marquée dans
// l'audit (release.verdict.emitted), jamais répétée.

import type { Queryable } from '../utils/db'
import type { Verdict } from '#shared/analysis'

export interface ReleaseVerdictEvent {
  scanId: string
  projectId: string
  verdict: Verdict
  /** Empreinte du rapport signé ; null pour une analyse de branche. */
  reportSha256: string | null
}

export type ReleaseVerdictListener = (db: Queryable, event: ReleaseVerdictEvent) => Promise<void> | void

const listeners: ReleaseVerdictListener[] = []

/** Ajoute un écouteur ; rend la fonction qui le retire. */
export function onReleaseVerdict(listener: ReleaseVerdictListener): () => void {
  listeners.push(listener)
  return () => {
    const i = listeners.indexOf(listener)
    if (i >= 0) listeners.splice(i, 1)
  }
}

/** Appelle chaque écouteur ; rend le nombre d'écouteurs en erreur (jamais levé). */
export async function emitReleaseVerdict(db: Queryable, event: ReleaseVerdictEvent): Promise<number> {
  let failed = 0
  for (const l of [...listeners]) {
    try {
      await l(db, event)
    }
    catch (err) {
      failed++
      console.error(`[release] verdict listener failed for scan ${event.scanId}: ${(err as Error)?.message ?? 'error'}`)
    }
  }
  return failed
}

/** Tests : retire tous les écouteurs. */
export function clearReleaseVerdictListeners(): void {
  listeners.length = 0
}
