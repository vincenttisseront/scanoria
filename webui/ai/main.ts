// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Point d'entrée du service scanoria-ai (scanoria-ai.service), regroupé par
// scripts/bundle-services.mjs en .output/services/ai.mjs. Utilisateur
// scanoria-ai, sans privilège ; base par le socket local (authentification
// peer) ; configuration dans SCANORIA_AI_RUNTIME_DIR.

import pg from 'pg'
import { runLoop } from '../server/ai/runtime'

const databaseUrl = process.env.SCANORIA_AI_DATABASE_URL || 'postgresql:///scanoria?host=/var/run/postgresql'
const runtimeDir = process.env.SCANORIA_AI_RUNTIME_DIR || '/run/scanoria-ai'

const pool = new pg.Pool({ connectionString: databaseUrl, max: 3, idleTimeoutMillis: 30_000, application_name: 'scanoria-ai' })
pool.on('error', err => console.error('[scanoria-ai] idle client error:', err.message))

const controller = new AbortController()
for (const sig of ['SIGTERM', 'SIGINT'] as const) process.on(sig, () => controller.abort())

runLoop({ db: pool, runtimeDir }, controller.signal)
  .then(() => pool.end())
  .then(() => process.exit(0))
  .catch((err: Error) => {
    console.error('[scanoria-ai] fatal:', err.message)
    process.exit(1)
  })
