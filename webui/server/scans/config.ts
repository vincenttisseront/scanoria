// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Réglages de la file d'analyses (ARCHITECTURE § 12). Tout a un défaut sûr
// (principe 8) ; les chemins sont surchargeables pour les tests
// (SCANORIA_SCANS_DIR, SCANORIA_RUNNER_STATE : contrat 8).

export interface WorkerConfig {
  /** Racine de la file partagée avec scanoria-runner. */
  scansDir: string
  /** Capacité publiée par le runner ({slots, busy, updated_at}). */
  runnerStateFile: string
  /** Journaux des modules copiés par le worker (G20). */
  scanLogsDir: string
  /** Signe de vie du worker, lu par scanoria-selftest (worker.alive). */
  heartbeatFile: string
  /** Analyses en cours au plus par projet (G17). */
  perProjectLimit: number
  /** Période de la boucle principale, en millisecondes. */
  tickMs: number
  /** Période de la planification (runProjectSchedules). */
  scheduleMs: number
  /** Marge ajoutée au délai du plan avant de déclarer la tâche perdue (G12). */
  resultMarginS: number
  /** Relances automatiques d'une erreur infra (G12). */
  maxInfraRetries: number
  /** Recul de la première relance, doublé ensuite. */
  retryBaseS: number
  /** runner.json plus vieux que ce délai : runner considéré absent. */
  runnerStaleS: number
  /** 0.6 (V1) : demandes au helper root (prefetch-images après une image absente). */
  requestsDir: string
}

function int(value: string | undefined, fallback: number, min: number, max: number): number {
  const n = Number.parseInt(value ?? '', 10)
  return Number.isFinite(n) && n >= min && n <= max ? n : fallback
}

export function loadWorkerConfig(env: NodeJS.ProcessEnv = process.env): WorkerConfig {
  return {
    scansDir: env.SCANORIA_SCANS_DIR || '/var/lib/scanoria/scans',
    runnerStateFile: env.SCANORIA_RUNNER_STATE || '/run/scanoria/runner.json',
    scanLogsDir: env.SCANORIA_SCAN_LOGS_DIR || '/var/lib/scanoria/console/scan-logs',
    heartbeatFile: env.SCANORIA_WORKER_HEARTBEAT || '/var/lib/scanoria/console/worker.json',
    perProjectLimit: int(env.SCANORIA_SCANS_PER_PROJECT, 2, 1, 32),
    tickMs: int(env.SCANORIA_WORKER_TICK_MS, 2000, 50, 60_000),
    scheduleMs: int(env.SCANORIA_SCHEDULE_MS, 60_000, 100, 3_600_000),
    resultMarginS: int(env.SCANORIA_RESULT_MARGIN_S, 900, 1, 86_400),
    maxInfraRetries: int(env.SCANORIA_INFRA_RETRIES, 2, 0, 5),
    retryBaseS: int(env.SCANORIA_RETRY_BASE_S, 60, 0, 3600),
    runnerStaleS: int(env.SCANORIA_RUNNER_STALE_S, 120, 1, 86_400),
    requestsDir: env.NUXT_REQUESTS_DIR || '/var/lib/scanoria/requests',
  }
}
