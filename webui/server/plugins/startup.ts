// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Démarrage du serveur : informations de construction, migrations embarquées
// (serverAssets « migrations »), premier administrateur, ingestion des résultats.

import { prepareMigrations } from '../../migrate.mjs'
import { setBuildInfo } from '../utils/appliance'
import { closePool } from '../utils/db'
import { startConsole, stopConsole } from '../utils/runtime'

export default defineNitroPlugin((nitroApp) => {
  const config = useRuntimeConfig()
  setBuildInfo({ version: String(config.buildVersion ?? ''), sourceRepo: String(config.buildSourceRepo ?? '') })

  const loadMigrations = async () => {
    const storage = useStorage('assets:migrations')
    const keys = (await storage.getKeys()).filter(k => k.endsWith('.sql'))
    const files = await Promise.all(keys.map(async (key) => {
      const raw = await storage.getItemRaw(key)
      const content = typeof raw === 'string' ? raw : Buffer.from(raw as Uint8Array)
      return { name: key.split(':').pop()!, content }
    }))
    return prepareMigrations(files)
  }

  void startConsole(loadMigrations)

  nitroApp.hooks.hook('close', async () => {
    stopConsole()
    await closePool()
  })
})
