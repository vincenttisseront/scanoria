// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI des profils et de la configuration en code (0.7,
// chantier C : G8, G9, G10, J8, J5), repris par server/api/openapi.json.get.ts.
// Les schémas des corps sont générés depuis les schémas zod qui valident
// réellement les requêtes.

import { z } from 'zod'
import { profileCreateSchema, profileUpdateSchema } from './service'
import { profilePreviewSchema } from './preview'
import { projectProfilesSchema } from './assign'
import { importApplySchema, importPreviewSchema } from '../imports/service'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number }

export const PROFILE_OPS: Record<string, Record<string, Op>> = {
  '/api/profiles': {
    get: { summary: 'Scan profiles with hierarchy (enterprise → team → project) and locks (G8); ?archived=1 includes archived ones', role: 'viewer' },
    post: { summary: 'Create a custom profile; 409 E_PROFILE_LOCKED {violations} when it would loosen an inherited lock', role: 'admin', body: 'ProfileCreate', status: 201 },
  },
  '/api/profiles/preview': { post: { summary: 'Preview a profile before saving (G10): resolved modules, modules to install, estimated duration and resources, coverage on a repository', role: 'operator', body: 'ProfilePreview' } },
  '/api/profiles/{id}': {
    get: { summary: 'Profile, inherited locks, effective profile (contract 29) and projects using it', role: 'viewer' },
    patch: { summary: 'Update a profile; inherited locks can only be hardened (409 E_PROFILE_LOCKED)', role: 'admin', body: 'ProfileUpdate' },
  },
  '/api/profiles/{id}/archive': { post: { summary: 'Archive or restore a profile (never a built-in profile, one in use or a parent)', role: 'admin', body: 'Archive' } },
  '/api/projects/{id}/profiles': {
    get: { summary: 'Effective profile per trigger (G9), locks, imposed "no AI" and repository configuration state (.scanoria.yml, J8)', role: 'viewer' },
    put: { summary: 'Profiles per trigger (default, pr, nightly, release; null = default); a looser lock needs admin (403 E_PROFILE_LOOSER)', role: 'operator', body: 'ProjectProfiles' },
  },
  '/api/projects/{id}/imports/preview': { post: { summary: 'Effect of importing existing exception configurations (J5) from the repository and optionally a SonarQube, Dependency-Track or DefectDojo instance; nothing is written', role: 'admin', body: 'ImportPreview' } },
  '/api/projects/{id}/imports/apply': { post: { summary: 'File the imported exception requests (requested_via tool-import, never approved); the instance token is erased', role: 'admin', body: 'ImportApply' } },
  '/api/config/schema': { get: { summary: 'JSON schema of .scanoria.yml (J8)', role: 'viewer' } },
  '/api/config/export': { get: { summary: 'Whole appliance configuration as versioned YAML (J8): projects, profiles, gates, rulesets, severity maps, triage rules; never a secret', role: 'admin' } },
  '/api/config/import/preview': { post: { summary: 'Differences between an exported configuration and the appliance; nothing is written; returns the digest required to apply', role: 'admin', body: 'ConfigImport' } },
  '/api/config/import/apply': { post: { summary: 'Apply a previewed configuration (same digest) in one transaction, audited; 409 E_CONFIG_DIGEST, 422 E_CONFIG_INVALID {issues}', role: 'admin', body: 'ConfigApply' } },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function profileSchemas(): Record<string, Record<string, unknown>> {
  return {
    ProfileCreate: json(profileCreateSchema),
    ProfileUpdate: json(profileUpdateSchema),
    ProfilePreview: json(profilePreviewSchema),
    ProjectProfiles: json(projectProfilesSchema),
    Archive: json(z.strictObject({ archived: z.boolean() })),
    ImportPreview: json(importPreviewSchema),
    ImportApply: json(importApplySchema),
    ConfigImport: json(z.strictObject({ yaml: z.string().min(1) })),
    ConfigApply: json(z.strictObject({ yaml: z.string().min(1), digest: z.string().regex(/^[0-9a-f]{64}$/) })),
  }
}
