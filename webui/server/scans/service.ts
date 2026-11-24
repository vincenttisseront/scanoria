// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Boucle de scanoria-worker : passes régulières de ScanWorker, planification
// des projets (A), relevés des modules permanents (F14), signe de vie pour
// scanoria-selftest (worker.alive) et arrêt propre sur SIGTERM : la passe en cours se termine, rien n'est perdu
// (l'état est en base et dans la file ; une analyse déposée reprend au
// redémarrage).

import { constants } from 'node:fs'
import { mkdir, open, rename } from 'node:fs/promises'
import { dirname } from 'node:path'
import type pg from 'pg'
import type { WorkerConfig } from './config'
import { enqueueScan } from './enqueue'
import { runRecorrelation } from './recorrelate'
import { purgeCache } from './orchestration'
import type { Integrations } from './integrations'
import { ScanWorker, type WorkerPaths } from './worker'
import { UsageTask } from '../usage/samples'

export interface ServiceOptions {
  pool: pg.Pool
  cfg: WorkerConfig
  paths: WorkerPaths
  integrations: Integrations
  version?: string
  log?: (msg: string) => void
  /** État publié par le service root : relevés des modules permanents (F14, contrat 11). */
  stateFile?: string
}

export class WorkerService {
  readonly worker: ScanWorker
  private stopping = false
  private running: Promise<void> | null = null
  private timer: NodeJS.Timeout | undefined
  private lastSchedule = 0
  private lastPurge = 0
  private lastCachePurge = 0
  private wake: (() => void) | null = null
  private readonly log: (msg: string) => void
  private readonly usage: UsageTask | null

  constructor(private readonly opts: ServiceOptions) {
    this.log = opts.log ?? (msg => console.log(`[worker] ${msg}`))
    this.worker = new ScanWorker(opts.pool, opts.cfg, opts.paths, opts.integrations, this.log)
    this.usage = opts.stateFile ? new UsageTask(opts.pool, { stateFile: opts.stateFile, log: this.log }) : null
  }

  /** Une itération : relevé, dépôt, planification (au plus une fois par période), signe de vie. */
  async iterate(now = new Date()): Promise<void> {
    try {
      await this.worker.tick(now)
    }
    catch (e) {
      this.log(`tick failed: ${(e as Error).message}`)
    }
    if (now.getTime() - this.lastSchedule >= this.opts.cfg.scheduleMs) {
      this.lastSchedule = now.getTime()
      try {
        await this.opts.integrations.runProjectSchedules(this.opts.pool, now, enqueueScan)
      }
      catch (e) {
        this.log(`schedules failed: ${(e as Error).message}`)
      }
      // 0.5 (B, contrat 16) : bases plus récentes → re-corrélations en file.
      await runRecorrelation(this.opts.pool, this.opts.paths, now, this.log)
        .catch((e: unknown) => this.log(`recorrelation failed: ${(e as Error).message}`))
    }
    // 0.6 (V4) : éviction du cache de résultats, chaque heure.
    if (now.getTime() - this.lastCachePurge >= 3600_000) {
      this.lastCachePurge = now.getTime()
      await purgeCache(this.opts.pool, this.opts.paths).catch((e: unknown) => this.log(`result cache purge failed: ${(e as Error).message}`))
    }
    if (now.getTime() - this.lastPurge >= 24 * 3600_000) {
      this.lastPurge = now.getTime()
      await this.worker.purgeOrphanLogs().catch(() => 0)
    }
    await this.usage?.iterate(now)
    await this.heartbeat(now).catch(e => this.log(`heartbeat failed: ${(e as Error).message}`))
  }

  async heartbeat(now = new Date()): Promise<void> {
    const file = this.opts.cfg.heartbeatFile
    await mkdir(dirname(file), { recursive: true, mode: 0o700 })
    const tmp = `${file}.${process.pid}.tmp`
    const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW, 0o640)
    try {
      await fh.writeFile(JSON.stringify({ pid: process.pid, version: this.opts.version ?? null, at: now.toISOString() }))
    }
    finally {
      await fh.close()
    }
    await rename(tmp, file)
  }

  /** Lance la boucle ; se résout quand stop() a été appelé et la passe en cours terminée. */
  start(): Promise<void> {
    this.running = (async () => {
      while (!this.stopping) {
        await this.iterate()
        if (this.stopping) break
        await new Promise<void>((resolve) => {
          this.wake = resolve
          this.timer = setTimeout(resolve, this.opts.cfg.tickMs)
        })
        this.wake = null
      }
    })()
    return this.running
  }

  async stop(): Promise<void> {
    this.stopping = true
    if (this.timer) clearTimeout(this.timer)
    this.wake?.()
    await this.running
  }
}
