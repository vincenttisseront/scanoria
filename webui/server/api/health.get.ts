// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// GET /api/health (sans authentification, docs/ARCHITECTURE.md § 3.6) :
// 200 {"status":"ok","version":"X.Y.Z","db":"ok"} ou 503 "status":"error".
// Aucune autre information.

import { defineEventHandler, setResponseStatus } from 'h3'
import { getConfig } from '../utils/config'
import { getPool } from '../utils/db'
import { getRunningVersion } from '../utils/appliance'
import { consoleReady } from '../utils/runtime'

export default defineEventHandler(async (event) => {
  const version = await getRunningVersion(getConfig().versionFile)
  let db: 'ok' | 'error' = 'error'
  if (consoleReady()) {
    try {
      await getPool().query('SELECT 1')
      db = 'ok'
    }
    catch {
      db = 'error'
    }
  }
  if (db !== 'ok') setResponseStatus(event, 503)
  return { status: db === 'ok' ? 'ok' : 'error', version, db }
})
