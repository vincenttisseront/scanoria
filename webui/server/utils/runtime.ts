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
import { syncIntel } from '../intel/import'
import { backfillCorrelationKeys } from '../findings/correlation'
import { packageDatesTick } from '../sbom/dates'
import { vigilanceTick } from '../vigilance/tick'
import { triageTick } from '../findings/tick'
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
    // 0.5 (B, H5) : dates de publication des composants, par le helper.
    await packageDatesTick(pool, cfg.requestsDir)
    ticks += 1
    // H3 (0.5) : exports EPSS et KEV du helper importés environ chaque minute.
    if (ticks % 12 === 1) await syncIntelNow(pool, cfg.modulesStateFile)
    // 0.6 (B) : versions figées, essais F13, canaris G14, vulnérabilités de l'appliance F19.
    if (ticks % 12 === 1) await vigilanceTick(pool, cfg)
    // 0.7 (B) : échéance des exceptions (F5), règles de tri échues (F4), verdicts recalculés.
    if (ticks % 720 === 1) await triageTick(pool).catch((e: unknown) => console.error('[triage] tick error:', (e as Error).message))
    if (ticks % 720 === 1) {
      await purgeSessions(pool)
      await purgeOldUploads(cfg.uploadsDir, await referencedUploads(pool))
    }
  }
  catch (err) {
    console.error('[ingest] error:', (err as Error).message)
  }
  finally {
    ingestRunning = false
  }
}

async function syncIntelNow(pool: ReturnType<typeof getPool>, modulesStateFile: string): Promise<void> {
  const results = await syncIntel(pool, { modulesStateFile }).catch((err: Error) => {
    console.error('[intel] error:', err.message)
    return []
  })
  for (const r of results) {
    if (r.action === 'imported') console.log(`[intel] ${r.feed}: ${r.rows} CVE imported (${r.changed} changed, ${r.cleared} cleared, ${r.skipped} invalid lines skipped)`)
    else if (r.action === 'cleared') console.log(`[intel] ${r.feed}: feed removed, ${r.cleared} values cleared`)
    else if (r.action === 'error') console.error(`[intel] ${r.feed}: import failed (${r.error})`)
  }
}

/** Archives encore utilisées : celle d'un projet, ou d'une analyse pas encore terminée. */
async function referencedUploads(pool: ReturnType<typeof getPool>): Promise<Set<string>> {
  const { rows } = await pool.query<{ id: string }>(
    `SELECT upload_id::text AS id FROM projects WHERE upload_id IS NOT NULL
     UNION SELECT upload_id::text FROM scans WHERE upload_id IS NOT NULL AND status IN ('queued', 'dispatched', 'running', 'ingesting')`,
  )
  return new Set(rows.map(r => r.id))
}

/**
 * Les téléversements de plus de 24 h sont supprimés (le helper les a copiés),
 * sauf l'archive source d'un projet ou d'une analyse en cours.
 */
async function purgeOldUploads(uploadsDir: string, keep: Set<string>): Promise<void> {
  let names: string[]
  try {
    names = await readdir(uploadsDir)
  }
  catch {
    return
  }
  const limit = Date.now() - 24 * 3600_000
  for (const name of names) {
    if (!UUID_V4_RE.test(name) || keep.has(name.toLowerCase())) continue
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
  // F16 (0.5) : clé de recoupement des résultats d'avant la 0.5, par lots, une seule fois.
  void backfillCorrelationKeys(getPool())
    .then((r) => {
      if (r.scanned) console.log(`[correlation] backfill: ${r.scanned} findings scanned, ${r.updated} keys set`)
    })
    .catch(err => console.error('[correlation] backfill error:', (err as Error).message))
  ingestTimer = setInterval(() => void ingestNow(), cfg.ingestIntervalMs)
  ingestTimer.unref()
  void ingestNow()
}

export function stopConsole(): void {
  stopped = true
  if (ingestTimer) clearInterval(ingestTimer)
}
