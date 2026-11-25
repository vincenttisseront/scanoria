// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Tâches et résultats échangés avec scanoria-runner (contrat 8,
// scan-job.schema.json et scan-result.schema.json). Les contraintes zod
// reprennent exactement celles des schémas JSON (tests/unit/worker-contract).

import { z } from 'zod'
import { COMMIT_RE, ERROR_CLASSES } from '#shared/analysis'
import { MODULE_ID_RE, TIMESTAMP_RE, UUID_V4_RE } from '#shared/schemas'

export const GIT_URL_RE = /^(https:\/\/[^?#@\s]+|ssh:\/\/[A-Za-z0-9._-]+@[^?#\s]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[^?#\s]+)$/
export const GIT_REF_RE = /^[A-Za-z0-9._/-]+$/
export const GIT_REF_FORBIDDEN_RE = /(^-|\.\.|\/\/|@\{)/
export const RESULT_PATH_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/
export const RESULT_PATH_FORBIDDEN_RE = /(^|\/)\.\.?(\/|$)/
export const ERROR_CODE_RE = /^E_[A-Z_]+$/
export const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
export const SSH_KEY_RE = /^-{5}BEGIN OPENSSH PRIVATE KEY-{5}/

const uuid = z.string().regex(UUID_V4_RE)
const timestamp = z.string().regex(TIMESTAMP_RE)
const moduleId = z.string().regex(MODULE_ID_RE)
const resultPath = z.string().max(255).regex(RESULT_PATH_RE).refine(p => !RESULT_PATH_FORBIDDEN_RE.test(p))

/** purl d'une tâche de re-corrélation : forme bornée, sans espace ni caractère de contrôle. */
export const SBOM_PURL_RE = /^pkg:[a-z][a-z0-9.+-]{0,31}\/[\x21-\x7e]{1,1000}$/
export const SBOM_JOB_MAX_COMPONENTS = 20_000
const sbomPurl = z.string().max(1024).regex(SBOM_PURL_RE)

export const gitRef = z.string().min(1).max(255).regex(GIT_REF_RE).refine(r => !GIT_REF_FORBIDDEN_RE.test(r))

const tokenCredential = z.strictObject({
  kind: z.literal('token'),
  username: z.string().max(255).regex(/^[^:\s]+$/).optional(),
  token: z.string().min(1).max(4096).regex(/^[\x21-\x7e]+$/),
})
const sshCredential = z.strictObject({
  kind: z.literal('ssh-key'),
  private_key: z.string().max(16384).regex(SSH_KEY_RE),
  known_hosts: z.string().min(1).max(16384),
})
export const jobCredential = z.union([z.null(), tokenCredential, sshCredential])
export type JobCredential = z.infer<typeof jobCredential>

export const scanJobSchema = z.strictObject({
  schema: z.literal(1),
  id: uuid,
  scan_id: uuid,
  // Facultatif (0.4, contrat 12) : clé de projet des scanners reliés à un service.
  project_id: uuid.optional(),
  created_at: timestamp,
  source: z.union([
    z.strictObject({
      kind: z.literal('git'),
      url: z.string().max(2048).regex(GIT_URL_RE),
      ref: gitRef,
      // Facultatif (0.4) : branche par défaut du projet, pour scan.refs « default-branch ».
      default_branch: gitRef.optional(),
      commit: z.string().regex(COMMIT_RE).optional(),
      history: z.enum(['shallow', 'full']),
      credential: jobCredential.optional(),
    }),
    z.strictObject({ kind: z.literal('archive'), upload_id: uuid }),
    // 0.5 (B, contrat 16) : re-corrélation ; le runner écrit lui-même le SBOM à partir de ces purl.
    z.strictObject({ kind: z.literal('sbom'), scan_id: uuid, components: z.array(sbomPurl).min(1).max(SBOM_JOB_MAX_COMPONENTS) }),
  ]),
  // 0.6 (V4, contrat 21) : le runner peut reprendre une sortie du cache de résultats.
  cache: z.boolean().optional(),
  modules: z.array(z.strictObject({
    id: moduleId,
    version: z.string().min(1).max(64),
    options: z.record(z.string(), z.unknown()).optional(),
    // 0.6 (B, contrats 24 et 25) : version figée ou candidate d'un essai.
    image_digest: z.string().regex(/^sha256:[0-9a-f]{64}$/).optional(),
    // 0.6 (V3, V5) : modules de la tâche à terminer avant celui-ci.
    after: z.array(moduleId).max(64).refine(l => new Set(l).size === l.length).optional(),
  })).min(1).max(64).refine(list => new Set(list.map(m => JSON.stringify(m))).size === list.length),
  // 0.6 (B, contrat 25) : analyse d'essai F13.
  trial: z.boolean().optional(),
})
export type ScanJob = z.infer<typeof scanJobSchema>

const runnerError = z.strictObject({
  code: z.string().regex(ERROR_CODE_RE),
  class: z.enum(ERROR_CLASSES),
  message: z.string().max(2000),
})
export type RunnerError = z.infer<typeof runnerError>

export const RESULT_MODULE_STATUSES = ['ok', 'error', 'timeout', 'oom', 'invalid-output', 'missing', 'skipped', 'not-applicable'] as const
const cacheKey = z.string().regex(/^[0-9a-f]{64}$/)

export const scanResultSchema = z.strictObject({
  schema: z.literal(1),
  id: uuid,
  scan_id: uuid,
  status: z.enum(['ok', 'error']),
  error: runnerError.nullable().optional(),
  started_at: timestamp,
  finished_at: timestamp,
  source: z.strictObject({
    kind: z.enum(['git', 'archive', 'sbom']),
    commit: z.string().regex(COMMIT_RE).nullable(),
    history: z.enum(['shallow', 'full', 'none']),
    files: z.number().int().min(0),
    bytes: z.number().int().min(0),
    skipped: z.array(z.strictObject({
      path: z.string().max(1024),
      reason: z.enum(['size', 'symlink', 'special', 'limit']),
    })).max(1000),
    // 0.6 (chantier C, contrat 22) : exclusions communes (G15), répertoire de travail (V9), miroir Git (V2).
    excluded: z.array(z.strictObject({
      pattern: z.string().min(1).max(100),
      count: z.number().int().min(1),
    })).max(100).optional(),
    workdir: z.enum(['tmpfs', 'disk']).optional(),
    mirror: z.enum(['hit', 'fetched', 'created', 'ephemeral']).optional(),
    // 0.6 (V4, V6) : empreinte du contenu de /src et détection par clés.
    tree: cacheKey.optional(),
    detection: z.record(z.string(), z.unknown()).optional(),
  }),
  modules: z.array(z.strictObject({
    id: moduleId,
    version: z.string().max(64),
    status: z.enum(RESULT_MODULE_STATUSES),
    error: runnerError.nullable().optional(),
    image_digest: z.string().regex(DIGEST_RE).nullable(),
    feeds: z.array(z.strictObject({
      id: moduleId,
      version: z.string().max(128).nullable(),
      // 0.6 (V7, G11) : répertoire de la version de la base montée pour cette analyse.
      revision: z.string().regex(/^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/).optional(),
      updated_at: timestamp.nullable(),
    })),
    started_at: timestamp.nullable().optional(),
    finished_at: timestamp.nullable().optional(),
    exit_code: z.number().int().nullable().optional(),
    outputs: z.strictObject({ sarif: resultPath.optional(), cyclonedx: resultPath.optional() }),
    log: resultPath.nullable(),
    stats: z.strictObject({
      duration_ms: z.number().int().min(0).optional(),
      peak_memory_mb: z.number().int().min(0).optional(),
      cpu_ms: z.number().int().min(0).optional(),
    }).optional(),
    // 0.6 : clé sous laquelle ranger la sortie (V4), sortie reprise du cache, entrée lue et repli SBOM (V3).
    cache_key: cacheKey.optional(),
    reused_from: cacheKey.optional(),
    input: z.enum(['src', 'sbom']).optional(),
    sbom_fallback: z.boolean().optional(),
    // 0.7 (contrat 32) : module relié au relais IA (manifeste réellement lancé).
    ai_relay: z.boolean().optional(),
  })).max(64),
})
export type ScanResult = z.infer<typeof scanResultSchema>
export type ScanResultModule = ScanResult['modules'][number]

/** Capacité publiée par le runner (/run/scanoria/runner.json). */
export const runnerStateSchema = z.object({
  slots: z.number().int().min(0).max(1024),
  busy: z.number().int().min(0).max(1024),
  updated_at: timestamp,
})
export type RunnerState = z.infer<typeof runnerStateSchema>
