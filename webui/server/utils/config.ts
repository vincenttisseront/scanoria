// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Configuration de la console, lue dans l'environnement (/etc/scanoria/console.env,
// docs/ARCHITECTURE.md § 3.6). Valeurs par défaut = chemins de l'appliance.

export interface ConsoleConfig {
  databaseUrl: string
  stateFile: string
  requestsDir: string
  uploadsDir: string
  bootstrapDir: string
  publicFilesDir: string
  versionFile: string
  updateSourceFile: string
  /** Dernier index du catalogue vérifié par le helper (contrat 4). */
  catalogIndexFile: string
  /** État des modules publié par le helper (contrat 4). */
  modulesStateFile: string
  /** État DNS publié par le helper (contrat 4). */
  dnsStatusFile: string
  /** Prend l'adresse cliente dans X-Real-IP quand la connexion vient de la boucle locale (nginx). */
  trustProxy: boolean
  /** Applique les migrations au démarrage du serveur (en plus de migrate.mjs). */
  migrateOnStart: boolean
  /** Période de lecture des résultats du helper, en millisecondes. */
  ingestIntervalMs: number
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase())
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ConsoleConfig {
  const interval = Number.parseInt(env.NUXT_INGEST_INTERVAL_MS ?? '', 10)
  return {
    databaseUrl: env.NUXT_DATABASE_URL || env.DATABASE_URL || 'postgresql:///scanoria?host=/var/run/postgresql',
    stateFile: env.NUXT_STATE_FILE || '/run/scanoria/state.json',
    requestsDir: env.NUXT_REQUESTS_DIR || '/var/lib/scanoria/requests',
    uploadsDir: env.NUXT_UPLOADS_DIR || '/var/lib/scanoria/uploads',
    bootstrapDir: env.NUXT_BOOTSTRAP_DIR || '/var/lib/scanoria/bootstrap',
    publicFilesDir: env.NUXT_PUBLIC_FILES_DIR || '/var/lib/scanoria/public',
    versionFile: env.NUXT_VERSION_FILE || '/opt/scanoria/current/VERSION',
    updateSourceFile: env.NUXT_UPDATE_SOURCE_FILE || '/usr/share/scanoria/update-source.json',
    catalogIndexFile: env.NUXT_CATALOG_INDEX_FILE || '/var/lib/scanoria/catalog/catalog-index.json',
    modulesStateFile: env.NUXT_MODULES_STATE_FILE || '/var/lib/scanoria/modules/state.json',
    dnsStatusFile: env.NUXT_DNS_STATUS_FILE || '/var/lib/scanoria/dns/status.json',
    trustProxy: bool(env.NUXT_TRUST_PROXY, true),
    migrateOnStart: bool(env.NUXT_MIGRATE_ON_START, true),
    ingestIntervalMs: Number.isFinite(interval) && interval >= 200 ? interval : 5000,
  }
}

let current: ConsoleConfig | undefined
export function getConfig(): ConsoleConfig {
  current ??= loadConfig()
  return current
}
export function setConfig(config: ConsoleConfig): void {
  current = config
}
