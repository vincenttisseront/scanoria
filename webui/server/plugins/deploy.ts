// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.8 (D) : passe périodique du déploiement (J9, J11–J13, J16), une fois la
// console prête (migrations appliquées). Désactivable en test par
// NUXT_DEPLOY_INTERVAL_MS=0.

import { getPool } from '../utils/db'
import { consoleReady } from '../utils/runtime'
import { deployPass } from '../deploy/engine'

export default defineNitroPlugin((nitroApp) => {
  const raw = Number(process.env.NUXT_DEPLOY_INTERVAL_MS ?? 30_000)
  const every = Number.isFinite(raw) ? raw : 30_000
  if (every <= 0) return
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
