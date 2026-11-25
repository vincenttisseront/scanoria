// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI des jeux de règles gérés (G4, 0.7 chantier A),
// repris par server/api/openapi.json.get.ts ; schémas générés depuis les
// schémas zod qui valident réellement les requêtes.

import { z } from 'zod'
import { attachmentsSchema, createRulesetSchema } from './store'
import { rulesetTestSchema } from './engine'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number }

export const RULESET_OPS: Record<string, Record<string, Op>> = {
  '/api/rulesets': {
    get: { summary: 'Managed rulesets (G4: Opengrep, Semgrep, gitleaks, Checkov, KICS), query engine and archived=1', role: 'viewer' },
    post: { summary: 'Create a ruleset with its first version (typed or imported; Semgrep import requires license_ack)', role: 'admin', body: 'RulesetCreate', status: 201 },
  },
  '/api/rulesets/builtin': { get: { summary: 'Appliance built-in Opengrep rules (AGPL, read only, slug scanoria-base)', role: 'viewer' } },
  '/api/rulesets/validate': { post: { summary: 'Request validate-ruleset: the engine checks the content inside the module container, on samples', role: 'admin', body: 'RulesetValidate', status: 202 } },
  '/api/rulesets/{id}': {
    get: { summary: 'Ruleset, version history, attached profiles and available profiles', role: 'viewer' },
    patch: { summary: 'Rename, describe, archive or unarchive (archive refused while attached)', role: 'admin', body: 'RulesetUpdate' },
  },
  '/api/rulesets/{id}/versions': { post: { summary: 'New version (versions are never changed); static checks, audited', role: 'admin', body: 'RulesetVersion', status: 201 } },
  '/api/rulesets/{id}/versions/{version}': { get: { summary: 'Content of a version; diff=<other version> adds a line diff', role: 'viewer' } },
  '/api/rulesets/{id}/rollback': { post: { summary: 'Go back to a version: creates a new version with its content', role: 'admin', body: 'RulesetRollback', status: 201 } },
  '/api/rulesets/{id}/profiles': { put: { summary: 'Profiles that mount the ruleset, on the latest or a pinned version (one gitleaks ruleset per profile)', role: 'admin', body: 'RulesetProfiles' } },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function rulesetSchemas(): Record<string, Record<string, unknown>> {
  return {
    RulesetCreate: json(createRulesetSchema.extend({ content: z.string(), comment: z.string().nullable().optional(), origin: z.enum(['manual', 'import']).optional(), license_ack: z.boolean().optional() })),
    RulesetValidate: json(rulesetTestSchema),
    RulesetUpdate: json(z.strictObject({ name: z.string().optional(), description: z.string().nullable().optional(), archived: z.boolean().optional() })),
    RulesetVersion: json(z.strictObject({ content: z.string(), comment: z.string().nullable().optional(), origin: z.enum(['manual', 'import']).optional() })),
    RulesetRollback: json(z.strictObject({ version: z.number().int().min(1) })),
    RulesetProfiles: json(attachmentsSchema),
  }
}
