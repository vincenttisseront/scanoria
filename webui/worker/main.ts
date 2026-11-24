// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Point d'entrée de scanoria-worker (unité scanoria-worker.service, utilisateur
// scanoria, même base que la console). Construit par scripts/bundle-services.mjs
// en .output/services/worker.mjs, livré dans le lot à côté de la console.
// Les migrations restent faites par la console : le worker attend que le
// schéma des analyses soit présent.

import { readFileSync } from 'node:fs'
import pg from 'pg'
import { loadConfig } from '../server/utils/config'
import { loadWorkerConfig } from '../server/scans/config'
import { defaultIntegrations } from '../server/scans/integrations'
import { WorkerService } from '../server/scans/service'

const log = (msg: string) => console.log(`[worker] ${msg}`)

function version(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8').trim()
  }
  catch {
    return undefined
  }
}

async function waitSchema(pool: pg.Pool, stop: () => boolean): Promise<boolean> {
  for (let attempt = 1; !stop(); attempt++) {
    try {
      const r = await pool.query<{ ok: boolean }>(`SELECT to_regclass('public.scans') IS NOT NULL AS ok`)
      if (r.rows[0]?.ok) return true
      log('waiting for the console to apply database migrations')
    }
    catch (e) {
      log(`database unavailable (attempt ${attempt}): ${(e as Error).message}`)
    }
    await new Promise(resolve => setTimeout(resolve, Math.min(30_000, 2_000 * attempt)))
  }
  return false
}

async function main(): Promise<void> {
  const consoleCfg = loadConfig()
  const cfg = loadWorkerConfig()
  const pool = new pg.Pool({
    connectionString: consoleCfg.databaseUrl,
    max: 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: 'scanoria-worker',
  })
  pool.on('error', e => log(`idle client error: ${e.message}`))
  let stopping = false
  let service: WorkerService | undefined
  const onSignal = (sig: string) => {
    if (stopping) return
    stopping = true
    log(`${sig} received, finishing the current pass`)
    void service?.stop()
  }
  process.on('SIGTERM', () => onSignal('SIGTERM'))
  process.on('SIGINT', () => onSignal('SIGINT'))

  if (await waitSchema(pool, () => stopping)) {
    service = new WorkerService({
      pool,
      cfg,
      paths: { modulesStateFile: consoleCfg.modulesStateFile, catalogIndexFile: consoleCfg.catalogIndexFile, vigilanceStateFile: consoleCfg.vigilanceStateFile },
      integrations: defaultIntegrations,
      version: version(consoleCfg.versionFile),
      log,
      stateFile: consoleCfg.stateFile,
    })
    log(`started (scans ${cfg.scansDir}, ${cfg.perProjectLimit} per project)`)
    if (!stopping) await service.start()
  }
  await pool.end()
  log('stopped')
}

main().catch((e) => {
  console.error(`[worker] fatal: ${(e as Error).message}`)
  process.exit(1)
})
