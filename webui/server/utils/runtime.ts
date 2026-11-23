// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Démarrage de la console : migrations (si activées), premier administrateur,
// puis boucle d'ingestion des résultats du helper (toutes les 5 s environ).

import { readdir, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { applyMigrations, type Migration } from '../../migrate.mjs'
import { getConfig } from './config'
import { getPool } from './db'
import { consumeBootstrapAdmin } from './bootstrap'
import { IngestMemory, ingestResults, markRunning } from './ingest'
import { readPublishedState } from './appliance'
import { purgeSessions } from './sessions'
import { UUID_V4_RE } from '#shared/schemas'

let readyResolve: () => void
let isReady = false
const readyPromise = new Promise<void>((resolve) => {
  readyResolve = () => {
    isReady = true
    resolve()
  }
})

export function consoleReady(): boolean {
  return isReady
}

/** Attend que la base soit prête ; false après le délai. */
export async function waitReady(timeoutMs = 10_000): Promise<boolean> {
  if (isReady) return true
  let timer: NodeJS.Timeout | undefined
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), timeoutMs)
  })
  const result = await Promise.race([readyPromise.then(() => true), timeout])
  clearTimeout(timer)
  return result
}

const memory = new IngestMemory()
let ingestTimer: NodeJS.Timeout | undefined
let ingestRunning = false
let stopped = false
let ticks = 0

/** Une passe d'ingestion (aussi appelée au retour de chaque demande). */
export async function ingestNow(): Promise<void> {
  if (ingestRunning || !isReady) return
  ingestRunning = true
  try {
    const cfg = getConfig()
    const pool = getPool()
    const published = await readPublishedState(cfg.stateFile)
    const helper = published.state?.helper as { current?: { id?: string } | null } | undefined
    await markRunning(pool, helper?.current?.id)
    await ingestResults(pool, cfg.requestsDir, memory)
    ticks += 1
    if (ticks % 720 === 1) {
      await purgeSessions(pool)
      await purgeOldUploads(cfg.uploadsDir)
    }
  }
  catch (err) {
    console.error('[ingest] error:', (err as Error).message)
  }
  finally {
    ingestRunning = false
  }
}

/** Les téléversements de plus de 24 h sont supprimés (le helper les a copiés). */
async function purgeOldUploads(uploadsDir: string): Promise<void> {
  let names: string[]
  try {
    names = await readdir(uploadsDir)
  }
  catch {
    return
  }
  const limit = Date.now() - 24 * 3600_000
  for (const name of names) {
    if (!UUID_V4_RE.test(name)) continue
    const path = join(uploadsDir, name)
    try {
      const st = await stat(path)
      if (st.isDirectory() && st.mtimeMs < limit) await rm(path, { recursive: true, force: true })
    }
    catch {
      // ignoré
    }
  }
}

export async function startConsole(loadMigrations: () => Promise<Migration[]>): Promise<void> {
  const cfg = getConfig()
  for (let attempt = 1; !stopped; attempt++) {
    try {
      const pool = getPool()
      if (cfg.migrateOnStart) {
        const migrations = await loadMigrations()
        const client = await pool.connect()
        try {
          const applied = await applyMigrations(client, migrations, msg => console.log(`[migrate] ${msg}`))
          if (applied.length) console.log(`[migrate] applied: ${applied.join(', ')}`)
        }
        finally {
          client.release()
        }
      }
      const outcome = await consumeBootstrapAdmin(pool, cfg.bootstrapDir)
      if (outcome !== 'absent') console.log(`[bootstrap] admin.json: ${outcome}`)
      readyResolve()
      break
    }
    catch (err) {
      console.error(`[startup] attempt ${attempt} failed: ${(err as Error).message}`)
      await new Promise(resolve => setTimeout(resolve, Math.min(30_000, 2_000 * attempt)))
    }
  }
  if (stopped) return
  ingestTimer = setInterval(() => void ingestNow(), cfg.ingestIntervalMs)
  ingestTimer.unref()
  void ingestNow()
}

export function stopConsole(): void {
  stopped = true
  if (ingestTimer) clearInterval(ingestTimer)
}
