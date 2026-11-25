// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.8 (D) : passe périodique du déploiement (J9, J11–J13, J16), une fois la
// console prête (migrations appliquées), et passe immédiate à chaque verdict
// de release émis par le chantier A (contrat 40, onReleaseVerdict).
// Désactivable en test par NUXT_DEPLOY_INTERVAL_MS=0.

import { getPool } from '../utils/db'
import { consoleReady } from '../utils/runtime'
import { deployPass } from '../deploy/engine'
import { registerDeployListeners } from '../deploy/listen'
import { onReleaseVerdict } from '../release/events'

export default defineNitroPlugin((nitroApp) => {
  const raw = Number(process.env.NUXT_DEPLOY_INTERVAL_MS ?? 30_000)
  const every = Number.isFinite(raw) ? raw : 30_000
  if (every <= 0) return
  // Contrat 40 : l'événement de A porte (db, event) ; l'écouteur de D lit l'événement seul.
  registerDeployListeners(listener => onReleaseVerdict((_db, event) => listener(event)))
  let busy = false
  const tick = async () => {
    if (busy || !consoleReady()) return
    busy = true
    try {
      await deployPass(getPool())
    }
    finally {
      busy = false
    }
  }
  const timer = setInterval(() => void tick(), Math.max(5_000, every))
  timer.unref()
  nitroApp.hooks.hook('close', () => {
    clearInterval(timer)
  })
})
