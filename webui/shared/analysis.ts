// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Contrats partagés des analyses (0.3, docs/ARCHITECTURE.md § 12). Ils
// reprennent À L'IDENTIQUE les contraintes de 003_analyses.sql et des schémas
// scan-job / scan-result ; tests/unit/analysis.test.ts compare les deux.
// Fichier partagé entre chantiers : ajout seulement.

import { z } from 'zod'
import { MODULE_ID_RE } from './schemas'

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]
/** Rang d'une gravité : plus grand = plus grave. */
export const SEVERITY_RANK: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

/** Catégories de modules (catalog/schema/module.schema.json). */
export const CATEGORIES = [
  'quality', 'sast', 'secrets', 'sca', 'iac', 'container', 'sbom', 'dast',
  'lint', 'licenses', 'vuln-management', 'ci',
] as const
export type Category = (typeof CATEGORIES)[number]
/** Catégorie des modules système (git-fetch, chantier B) : jamais résolue dans un profil ni lancée par une analyse. */
export const SYSTEM_CATEGORY = 'system' as const

export const SCAN_TRIGGERS = ['manual', 'schedule', 'commit', 'webhook', 'api', 'release', 'replay'] as const
export type ScanTrigger = (typeof SCAN_TRIGGERS)[number]
/** Ordonnancement (G17) : release > PR > manuel > planifié. */
export const SCAN_PRIORITY: Record<ScanTrigger, number> = {
  release: 90, webhook: 70, api: 70, manual: 50, replay: 40, commit: 30, schedule: 10,
}

export const SCAN_STATUSES = ['queued', 'dispatched', 'running', 'ingesting', 'done', 'error', 'cancelled'] as const
export type ScanStatus = (typeof SCAN_STATUSES)[number]
export const SCAN_MODULE_STATUSES = [
  'pending', 'running', 'ok', 'error', 'timeout', 'oom', 'invalid-output', 'missing', 'skipped',
] as const
export type ScanModuleStatus = (typeof SCAN_MODULE_STATUSES)[number]
/** G12 : infra = relancée automatiquement ; tool / input = non concluant. */
export const ERROR_CLASSES = ['infra', 'tool', 'input'] as const
export type ErrorClass = (typeof ERROR_CLASSES)[number]

export const VERDICTS = ['passed', 'failed', 'inconclusive'] as const
export type Verdict = (typeof VERDICTS)[number]

export const FINDING_STATUSES = ['new', 'confirmed', 'false-positive', 'accepted', 'fixed'] as const
export type FindingStatus = (typeof FINDING_STATUSES)[number]
export const SECRET_STATES = ['to-revoke', 'revoked', 'false-positive'] as const
export const EXCEPTION_KINDS = ['path', 'rule', 'vuln', 'finding', 'module'] as const
export const FORGE_KINDS = ['forgejo', 'github', 'gitlab'] as const
export const SCHEDULES = ['none', 'daily', 'on-commit'] as const

export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/
export const COMMIT_RE = /^[0-9a-f]{40,64}$/
export const FINGERPRINT_RE = /^[0-9a-f]{64}$/
export const API_TOKEN_RE = /^scn_[A-Za-z0-9]{40}$/

const severity = z.enum(SEVERITIES)

/** Règles d'un quality gate (table gates.rules). Défauts = gate « defaut ». */
export const GateRules = z.object({
  new_code_only: z.boolean().default(true),
  max_secrets: z.number().int().min(0).default(0),
  vuln_block_from: severity.nullable().default('high'),
  sast_block_from: severity.nullable().default('high'),
  iac_block_from: severity.nullable().default('high'),
  block_malicious: z.literal(true).default(true), // H4 : jamais désactivable
  inconclusive_blocks: z.literal(true).default(true), // G13 : non concluant = bloquant
  // 0.5 (contrat 15, figé par l'intégrateur)
  license_denied_blocks: z.boolean().default(true), // F8 : licence « interdite » bloquante
  kev_blocks: z.boolean().default(true), // H3 : CVE du catalogue KEV bloquante, quelle que soit sa gravité
  epss_block_from: z.number().min(0).max(1).nullable().default(0.1), // H3 : EPSS au-dessus du seuil bloquant ; null = ignoré
  quarantine_days: z.number().int().min(0).max(90).default(7), // H5 : 0 = pas de quarantaine
  // 0.6 (contrat 20, figé par l'intégrateur)
  feed_max_age_days: z.number().int().min(1).max(365).nullable().default(7), // G16 : base plus vieille = non concluant ; null = seulement signalé
}).strict()
export type GateRules = z.infer<typeof GateRules>

/** Raison d'un verdict, ordonnée par l'évaluateur ; base de I9 (verdict expliqué). */
export const VerdictReason = z.object({
  code: z.enum([
    'malicious-package', 'secret', 'vuln', 'sast', 'iac', 'other',
    'module-error', 'module-missing', 'output-invalid', 'coverage-gap', 'feed-stale',
    'license-denied', 'license-review', 'kev', 'epss', 'quarantine',
  ]),
  blocking: z.boolean(),
  count: z.number().int().min(0),
  severity: severity.nullable(),
  module: z.string().regex(MODULE_ID_RE).nullable(),
  finding_ids: z.array(z.string().uuid()).max(50),
  /** Actions qui débloqueraient : corriger, demander une exception, rafraîchir une base, relancer. */
  actions: z.array(z.enum(['fix', 'request-exception', 'refresh-feed', 'install-module', 'rerun', 'wait'])),
}).strict()
export const VerdictDetails = z.object({
  verdict: z.enum(VERDICTS),
  gate_id: z.string().uuid(),
  rules: GateRules,
  evaluated_at: z.string(),
  new_code_only: z.boolean(),
  counts: z.record(severity, z.number().int().min(0)),
  reasons: z.array(VerdictReason),
  exceptions_applied: z.array(z.object({ id: z.string().uuid(), reason: z.string(), expires_on: z.string() }).strict()),
}).strict()
export type VerdictDetails = z.infer<typeof VerdictDetails>

/**
 * Cible d'une exception (table exceptions.target), par type (chantiers D et E).
 * Une exception ne s'applique jamais à un résultat malveillant (H4).
 * - path : glob sur le chemin (« ** » traverse les dossiers, « * » et « ? » non) ;
 * - rule : règle d'un outil ; vuln : identifiant d'avis (CVE, GHSA, OSV…) ;
 * - finding : un résultat précis ; module : module du plan en échec (G13).
 */
const EXCEPTION_GLOB_RE = /^[^\0\n]{1,512}$/
export const ExceptionTargets = {
  path: z.object({ glob: z.string().regex(EXCEPTION_GLOB_RE), tool: z.string().min(1).max(64).optional() }).strict(),
  rule: z.object({ rule_id: z.string().min(1).max(255), tool: z.string().min(1).max(64).optional() }).strict(),
  vuln: z.object({ vuln_id: z.string().regex(/^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,120}$/), package: z.string().min(1).max(255).optional() }).strict(),
  finding: z.object({ finding_id: z.string().uuid() }).strict(),
  module: z.object({ module_id: z.string().regex(MODULE_ID_RE) }).strict(),
} as const
export type ExceptionKind = (typeof EXCEPTION_KINDS)[number]

/** Sujets d'une tâche IA (ai_tasks.subject_type, migration 006). */
export const AI_SUBJECT_TYPES = ['finding', 'scan', 'testbed', 'rule', 'module', 'license', 'appliance'] as const
export type AiSubjectType = (typeof AI_SUBJECT_TYPES)[number]
