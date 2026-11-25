// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contraintes partagées par la console (client et serveur). Elles reprennent
// À L'IDENTIQUE les schémas JSON de src/rootfs/usr/share/scanoria/requests/
// (docs/ARCHITECTURE.md § 5) ; tests/unit/schemas.test.ts compare les deux.

import { z } from 'zod'

export const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
export const TIMESTAMP_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$/
export const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/
export const ADDRESS_RE = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|[0-9a-f.]*:[0-9a-f:.]*)$/
export const FQDN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/
export const CIDR_RE = /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\/([0-9]|[12][0-9]|3[0-2])|[0-9a-f.]*:[0-9a-f:.]*\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))$/
export const VERSION_RE = /^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$/
export const CERT_PEM_RE = /^-----BEGIN CERTIFICATE-----\r?\n/
export const KEY_PEM_RE = /^-----BEGIN (EC |RSA )?PRIVATE KEY-----\r?\n/
export const WINDOW_START_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/
export const REPO_RE = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/
/** Nom d'un fichier de demande ou de résultat (§ 5.3). */
/** Adresse du serveur Ollama externe (set-ai-endpoint, CLAUDE.md § 3.5). */
export const AI_URL_RE = /^https?:\/\/(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})(:[0-9]{1,5})?\/?$/
/** Lots hors ligne et miroir (0.6, chantier A) : clé Ed25519 brute en base64, empreinte SHA-256. */
export const PUBLIC_KEY_B64_RE = /^[A-Za-z0-9+/]{43}=$/
export const KEY_FINGERPRINT_RE = /^[0-9a-f]{64}$/
export const MIRROR_URL_RE = /^https:\/\/(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})(:[0-9]{1,5})?\/?$/
/** Nom d'un fichier de demande ou de résultat (§ 5.3). */
export const REQUEST_FILE_RE = /^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$/

export const REQUEST_TYPES = [
  'set-hostname',
  'set-admin-networks',
  'issue-certificate',
  'import-certificate',
  'check-update',
  'apply-update',
  'rollback-update',
  'set-update-policy',
  'run-selftest',
  'check-dns',
  'refresh-catalog',
  'install-modules',
  'uninstall-module',
  'set-module-state',
  'update-module',
  'set-ai-endpoint',
  'refresh-feeds',
  'backup-module',
  'restore-module',
  'reset-service-admin',
  'package-dates',
  'export-bundle',
  'import-bundle',
  'set-mirror',
  'trust-key',
  'self-sbom',
  'run-canaries',
  'start-trial',
  'prefetch-images',
  'validate-ruleset',
  'sign-release-report',
] as const
export type RequestType = (typeof REQUEST_TYPES)[number]

export const RESULT_CODES = [
  'OK',
  'E_INVALID_NAME', 'E_NOT_REGULAR_FILE', 'E_BAD_OWNER', 'E_TOO_LARGE', 'E_INVALID_JSON',
  'E_UNKNOWN_TYPE', 'E_SCHEMA', 'E_ID_MISMATCH', 'E_DUPLICATE_ID', 'E_STALE', 'E_INVALID_PARAM',
  'E_PRECONDITION', 'E_LOCKOUT', 'E_NETWORK', 'E_NOT_FOUND', 'E_SIGNATURE', 'E_CHECKSUM',
  'E_ARCHIVE', 'E_VERSION', 'E_DISK_SPACE', 'E_CERT_INVALID', 'E_CERT_NAMES',
  'E_CERT_KEY_MISMATCH', 'E_CERT_EXPIRED', 'E_NO_PREVIOUS', 'E_HEALTH_ROLLED_BACK',
  'E_ROLLBACK_FAILED', 'E_TIMEOUT', 'E_INTERNAL',
  'E_RESOURCES', 'E_DEPENDENCY', 'E_CONFLICT', 'E_LICENSE', 'E_TESTBED',
  'E_AI_URL', 'E_AI_UNRESOLVED', 'E_AI_FORBIDDEN_ADDRESS', 'E_AI_CA',
  'E_FEED_UNAVAILABLE',
  'E_SERVICE_RESOURCES', 'E_BACKUP_FAILED', 'E_BACKUP_NOT_FOUND', 'E_BACKUP_INVALID',
  'E_SONAR_UNAVAILABLE', 'E_SONAR_ADMIN', 'E_SONAR_API',
  'E_DTRACK_UNAVAILABLE', 'E_DTRACK_ADMIN', 'E_DTRACK_API',
  'E_EXPORT_FAILED',
  'E_BUNDLE_INVALID', 'E_BUNDLE_SIGNATURE', 'E_BUNDLE_UNTRUSTED', 'E_BUNDLE_CHECKSUM',
  'E_BUNDLE_ARCHIVE', 'E_BUNDLE_IMAGE', 'E_BUNDLE_FEED', 'E_BUNDLE_SOURCE',
  'E_MIRROR_URL', 'E_MIRROR_UNRESOLVED', 'E_MIRROR_FORBIDDEN_ADDRESS', 'E_MIRROR_CA',
  'E_MIRROR_UNTRUSTED', 'E_MIRROR_UNREACHABLE',
  'E_KEY_INVALID',
  'E_CANARY_FAILED', 'E_TRIAL_INVALID', 'E_TRIAL_IMAGE', 'E_SELFSBOM_IMAGE', 'E_SELFSBOM_OUTPUT',
  'E_PREFETCH_FAILED', 'E_PREFETCH_UNKNOWN_IMAGE',
  // 0.7 (A, G4, contrat 34) : jeux de règles.
  'E_RULESET_INVALID', 'E_RULESET_MISSING', 'E_RULESET_NONE', 'E_RULESET_ENGINE_MISSING',
  'E_RELAY_UNAVAILABLE', 'E_RELAY_TOKEN',
  // 0.8 (A, contrat 37) : signature par la clé de l'appliance (communs avec D).
  'E_SIGN_TOO_LARGE', 'E_SIGN_ENCODING', 'E_SIGN_DIGEST', 'E_SIGN_CANONICAL', 'E_SIGN_SCHEMA', 'E_SIGN_SCAN', 'E_SIGN_KEY',
] as const
export type ResultCode = (typeof RESULT_CODES)[number]

export const ROLES = ['viewer', 'operator', 'admin'] as const
export type Role = (typeof ROLES)[number]
export const LOCALES = ['fr', 'en'] as const
export const CHANNELS = ['stable', 'prerelease'] as const
export const WEEK_DAYS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const

/** Modules (chantier 0.2-moteur) : mêmes motifs que les schémas de demandes. */
export const MODULE_ID_RE = /^[a-z0-9][a-z0-9-]{1,40}$/
export const MODULE_VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/
/** Identifiant d'une sauvegarde de module (0.4, chantier A) : horodatage UTC. */
export const BACKUP_ID_RE = /^[0-9]{8}T[0-9]{6}Z(-[0-9])?$/

const unique = (items: readonly unknown[]) => new Set(items).size === items.length

export const moduleIdSchema = z.string().regex(MODULE_ID_RE)
export const moduleVersionSchema = z.string().regex(MODULE_VERSION_RE)
/** Valeurs d'options d'un module (G3), validées par la console contre le schéma du manifeste. */
export const moduleOptionsSchema = z.record(z.string(), z.unknown())

export const fqdnSchema = z.string().min(4).max(253).regex(FQDN_RE)
export const versionSchema = z.string().regex(VERSION_RE)
export const uuidSchema = z.string().regex(UUID_V4_RE)
export const cidrSchema = z.string().max(49).regex(CIDR_RE)

export const maintenanceWindowSchema = z.strictObject({
  days: z.array(z.enum(WEEK_DAYS)).min(1).max(7).refine(unique, { message: 'duplicate' }),
  start: z.string().regex(WINDOW_START_RE),
  duration_minutes: z.int().min(30).max(480),
})

/** Paramètres de chaque type de demande (§ 5.1). */
export const requestParamSchemas = {
  'set-hostname': z.strictObject({ fqdn: fqdnSchema }),
  'set-admin-networks': z.strictObject({
    networks: z.array(cidrSchema).min(1).max(64).refine(unique, { message: 'duplicate' }),
    allow_self_lockout: z.boolean().optional(),
  }),
  'issue-certificate': z.strictObject({ force: z.boolean().optional() }),
  'import-certificate': z.strictObject({
    cert_pem: z.string().max(16384).regex(CERT_PEM_RE),
    key_pem: z.string().max(16384).regex(KEY_PEM_RE),
    chain_pem: z.string().max(65536).regex(CERT_PEM_RE).optional(),
  }),
  'check-update': z.strictObject({ channel: z.enum(CHANNELS).optional() }),
  'apply-update': z.union([
    z.strictObject({ source: z.literal('github'), version: versionSchema }),
    z.strictObject({ source: z.literal('upload'), upload_id: uuidSchema }),
  ]),
  'rollback-update': z.strictObject({ expected_current: versionSchema, expected_target: versionSchema }),
  'set-update-policy': z
    .strictObject({
      channel: z.enum(CHANNELS),
      auto_check: z.boolean(),
      auto_apply: z.boolean(),
      maintenance_window: maintenanceWindowSchema.nullable(),
    })
    .refine(p => !p.auto_apply || p.maintenance_window !== null, {
      message: 'auto_apply requires a maintenance window',
      path: ['maintenance_window'],
    }),
  'run-selftest': z.strictObject({ quick: z.boolean().optional() }),
  'check-dns': z.strictObject({}),
  'refresh-catalog': z.strictObject({}),
  'refresh-feeds': z.strictObject({
    ids: z.array(z.string().regex(MODULE_ID_RE)).min(1).max(50)
      .refine(a => new Set(a).size === a.length, 'duplicate ids').optional(),
  }),
  // 0.5 (B, H5) : dates de publication d'un lot de purl, cherchées par le helper.
  'package-dates': z.strictObject({
    purls: z.array(z.string().min(5).max(1024).regex(/^pkg:[a-z][a-z0-9.+-]{0,31}\/\S+$/)).min(1).max(2000)
      .refine(a => new Set(a).size === a.length, 'duplicate purls'),
  }),
  // 0.6 (C, V1) : images des modules installés et des versions figées (G6) présentes.
  'prefetch-images': z.strictObject({
    pins: z.array(z.strictObject({
      module_id: z.string().regex(MODULE_ID_RE),
      version: z.string().regex(MODULE_VERSION_RE),
      image_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/),
    })).max(500).optional(),
  }),
  // 0.7 (A, G4, I12) : un jeu de règles jugé par son moteur, confiné, sur des échantillons.
  'validate-ruleset': z.strictObject({
    engine: z.enum(['opengrep', 'semgrep', 'gitleaks', 'checkov', 'kics']),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    samples: z.array(z.strictObject({
      name: z.string().regex(/^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/),
      content: z.string().max(8192),
    })).max(10).optional(),
  }),
  'install-modules': z.strictObject({
    modules: z.array(z.strictObject({
      id: z.string().regex(MODULE_ID_RE),
      version: z.string().regex(MODULE_VERSION_RE),
      options: z.record(z.string(), z.unknown()),
    })).min(1).max(32),
    accept_licenses: z.array(z.string().regex(MODULE_ID_RE)).max(32).refine(unique, { message: 'duplicate' }),
  }),
  'uninstall-module': z.strictObject({ id: z.string().regex(MODULE_ID_RE), keep_data: z.boolean() }),
  'set-module-state': z.strictObject({ id: z.string().regex(MODULE_ID_RE), enabled: z.boolean() }),
  'update-module': z.strictObject({ id: z.string().regex(MODULE_ID_RE), version: z.string().regex(MODULE_VERSION_RE) }),
  'set-ai-endpoint': z.union([
    z.strictObject({
      enabled: z.literal(true),
      url: z.string().min(8).max(300).regex(AI_URL_RE),
      allow_insecure: z.boolean().optional(),
      token: z.boolean().optional(),
      ca_pem: z.string().min(64).max(16384).regex(CERT_PEM_RE).optional(),
      /** https seulement, jamais avec ca_pem : certificat du serveur accepté sans vérification. */
      skip_tls_verify: z.boolean().optional(),
    }).refine(p => !p.skip_tls_verify || (p.url.startsWith('https:') && p.ca_pem === undefined), { message: 'skip_tls_verify requires https and no ca_pem', path: ['skip_tls_verify'] }),
    z.strictObject({ enabled: z.literal(false) }),
  ]),
  'backup-module': z.strictObject({ id: z.string().regex(MODULE_ID_RE) }),
  'restore-module': z.strictObject({ id: z.string().regex(MODULE_ID_RE), backup: z.string().regex(BACKUP_ID_RE) }),
  'reset-service-admin': z.strictObject({ id: z.string().regex(MODULE_ID_RE) }),
  'export-bundle': z.union([
    z.strictObject({
      modules: z.array(z.string().regex(MODULE_ID_RE)).min(1).max(64).refine(unique, { message: 'duplicate' }),
      dry_run: z.boolean().optional(),
      keep: z.int().min(1).max(10).optional(),
    }),
    z.strictObject({
      schedule: z.strictObject({
        enabled: z.boolean(),
        every_days: z.int().min(1).max(31),
        keep: z.int().min(1).max(10),
        modules: z.array(z.string().regex(MODULE_ID_RE)).max(64).refine(unique, { message: 'duplicate' }),
      }),
    }),
    z.strictObject({ scheduled: z.literal(true) }),
  ]),
  'import-bundle': z.strictObject({ upload_id: uuidSchema }),
  'set-mirror': z.union([
    z.strictObject({
      enabled: z.literal(true),
      url: z.string().min(12).max(300).regex(MIRROR_URL_RE),
      fingerprint: z.string().regex(KEY_FINGERPRINT_RE),
      ca_pem: z.string().min(64).max(16384).regex(CERT_PEM_RE).optional(),
    }),
    z.strictObject({ enabled: z.literal(false) }),
  ]),
  'trust-key': z.union([
    z.strictObject({
      action: z.literal('add'),
      public_key: z.string().regex(PUBLIC_KEY_B64_RE),
      fingerprint: z.string().regex(KEY_FINGERPRINT_RE),
    }),
    z.strictObject({ action: z.literal('remove'), fingerprint: z.string().regex(KEY_FINGERPRINT_RE) }),
  ]),
  // 0.6 (B) : F19, G14, F13.
  'self-sbom': z.strictObject({}),
  'run-canaries': z.strictObject({
    ids: z.array(z.string().regex(MODULE_ID_RE)).min(1).max(64).refine(unique, { message: 'duplicate' }).optional(),
  }),
  'start-trial': z.strictObject({
    module: z.string().regex(MODULE_ID_RE),
    version: z.string().regex(MODULE_VERSION_RE),
    trial_id: uuidSchema.optional(),
    action: z.enum(['start', 'abandon']).optional(),
  }),
  // 0.8 (A, contrat 37) : rapport de release canonique à signer, porté en entier (4 Mio au plus).
  'sign-release-report': z.strictObject({
    scan_id: uuidSchema,
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    kind: z.literal('release-report'),
    content_b64: z.string().min(4).max(5592408).regex(/^[A-Za-z0-9+/]+={0,2}$/),
  }),
} satisfies Record<RequestType, z.ZodType>

export type RequestParams<T extends RequestType> = z.infer<(typeof requestParamSchemas)[T]>

export const requestedBySchema = z.strictObject({
  user_id: z.int().min(0).max(Number.MAX_SAFE_INTEGER),
  username: z.string().regex(USERNAME_RE),
  address: z.string().max(45).regex(ADDRESS_RE).optional(),
})

/** Enveloppe complète d'une demande (§ 5.2). */
export function envelopeSchema<T extends RequestType>(type: T) {
  return z.strictObject({
    version: z.literal(1),
    id: uuidSchema,
    type: z.literal(type),
    created_at: z.string().regex(TIMESTAMP_RE),
    requested_by: requestedBySchema,
    params: requestParamSchemas[type],
  })
}

const nullableTimestamp = z.string().regex(TIMESTAMP_RE).nullable()

/** Résultat écrit par scanoria-helper (§ 5.6). */
export const resultSchema = z
  .strictObject({
    version: z.literal(1),
    id: uuidSchema.nullable(),
    type: z.enum(REQUEST_TYPES).nullable(),
    origin: z.enum(['console', 'timer', 'firstboot', 'cli']),
    status: z.enum(['ok', 'error', 'rejected']),
    code: z.enum(RESULT_CODES),
    message: z.string().max(2000),
    received_at: z.string().regex(TIMESTAMP_RE),
    started_at: nullableTimestamp.optional(),
    finished_at: z.string().regex(TIMESTAMP_RE),
    output: z.record(z.string(), z.unknown()),
  })
  .refine(r => (r.status === 'ok') === (r.code === 'OK'), { message: 'status/code mismatch', path: ['code'] })
export type HelperResult = z.infer<typeof resultSchema>

// ---- Entrées de l'API de la console (hors protocole helper) ----

export const PASSWORD_MIN = 12
export const PASSWORD_MAX = 1024
export const passwordSchema = z.string().min(PASSWORD_MIN).max(PASSWORD_MAX)

export const loginSchema = z.strictObject({
  username: z.string().min(1).max(64),
  password: z.string().min(1).max(PASSWORD_MAX),
})

export const changePasswordSchema = z.strictObject({
  current_password: z.string().min(1).max(PASSWORD_MAX),
  new_password: passwordSchema,
})

export const accountUpdateSchema = z.strictObject({
  locale: z.enum(LOCALES).optional(),
  display_name: z.string().max(128).nullable().optional(),
})

export const userCreateSchema = z.strictObject({
  username: z.string().regex(USERNAME_RE),
  display_name: z.string().max(128).nullable().optional(),
  email: z.string().max(254).regex(/^[^@\s]+@[^@\s]+$/).nullable().optional(),
  role: z.enum(ROLES),
  locale: z.enum(LOCALES).optional(),
  password: passwordSchema,
})

export const userUpdateSchema = z.strictObject({
  display_name: z.string().max(128).nullable().optional(),
  email: z.string().max(254).regex(/^[^@\s]+@[^@\s]+$/).nullable().optional(),
  role: z.enum(ROLES).optional(),
  locale: z.enum(LOCALES).optional(),
  is_active: z.boolean().optional(),
  // J15 (0.7) : compte déclaré « agent » ou « bot » (demande, ne décide jamais).
  kind: z.enum(['human', 'agent', 'bot']).optional(),
})

export const userPasswordResetSchema = z.strictObject({
  password: passwordSchema,
  must_change_password: z.boolean().optional(),
})

export const auditQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
  action: z.string().max(64).regex(/^[a-z0-9.-]+$/).optional(),
  outcome: z.enum(['success', 'failure', 'denied']).optional(),
  actor: z.string().max(64).regex(/^[a-z0-9._-]+$/).optional(),
})

export const applyUpdateBodySchema = requestParamSchemas['apply-update']

export const UPLOAD_FILE_NAMES = ['release.json', 'SHA256SUMS', 'SHA256SUMS.sig'] as const
export const ARCHIVE_NAME_RE = /^scanoria-(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.tar\.zst$/

/** Rang des rôles (table roles). */
export const ROLE_RANK: Record<Role, number> = { viewer: 10, operator: 20, admin: 30 }
export function hasRole(actual: Role, required: Role): boolean {
  return ROLE_RANK[actual] >= ROLE_RANK[required]
}

// ---- Catalogue (0.2) ----

const planModuleSchema = z.strictObject({
  id: moduleIdSchema,
  version: moduleVersionSchema.optional(),
  options: moduleOptionsSchema.optional(),
})

const planShape = {
  modules: z.array(planModuleSchema).min(1).max(32).optional(),
  pack: moduleIdSchema.optional(),
}
const onePlanSource = (b: { modules?: unknown, pack?: unknown }) => (b.modules === undefined) !== (b.pack === undefined)

/** Plan d'installation : une liste de modules, ou un pack (F11). */
export const planBodySchema = z.strictObject(planShape).refine(onePlanSource, { message: 'modules or pack' })

/** Installation : plan + licences acceptées explicitement (§ 2.1). */
export const installBodySchema = z
  .strictObject({ ...planShape, accept_licenses: z.array(moduleIdSchema).max(32).default([]) })
  .refine(onePlanSource, { message: 'modules or pack' })

export const moduleStateBodySchema = z.strictObject({ enabled: z.boolean() })
export const moduleUpdateBodySchema = z.strictObject({
  version: moduleVersionSchema.optional(),
  accept_licenses: z.array(moduleIdSchema).max(32).default([]),
})
export const moduleUninstallBodySchema = z.strictObject({ keep_data: z.boolean() })
/** Sauvegarde et restauration d'un module permanent (0.4, chantier A). */
export const moduleBackupBodySchema = z.strictObject({})
export const moduleRestoreBodySchema = z.strictObject({ backup: z.string().regex(BACKUP_ID_RE) })
