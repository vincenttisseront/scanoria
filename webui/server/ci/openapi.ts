// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI de l'intégration CI (0.8, chantier C : J2, J3,
// J4), repris par server/api/openapi.json.get.ts. Les schémas des corps sont
// générés depuis les schémas zod qui valident réellement les requêtes.

import { z } from 'zod'
import { bindingCreateSchema, bindingPatchSchema, ciSettingsSchema, issuerCreateSchema, issuerPatchSchema, protectionDecisionSchema } from './schemas'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number, token?: boolean }

export const CI_OPS: Record<string, Record<string, Op>> = {
  '/api/ci/issuers': {
    get: { summary: 'Trusted CI OIDC issuers (J4) with binding count and cached JWKS date, and OIDC refusals counted since start, by reason', role: 'admin' },
    post: { summary: 'Add a trusted OIDC issuer (HTTPS only, audience scanoria by default); 409 E_EXISTS', role: 'admin', body: 'OidcIssuerCreate', status: 201 },
  },
  '/api/ci/issuers/{id}': { patch: { summary: 'Enable or disable an OIDC issuer: every token it signs is refused while disabled, never re-enabled automatically', role: 'admin', body: 'OidcIssuerPatch' } },
  '/api/ci/templates': { get: { summary: 'Official CI templates (J3): list, or one file (query file, closed list); with query project, GitHub and Forgejo workflows are rendered for that project (console URL, project id, pull or push mode, client digest)', role: 'viewer' } },
  '/api/projects/{id}/ci': { get: { summary: 'CI integration of a project: release mode, autonomous chain (J16), detected CI and chosen template (J3), integration pull request and proposed branch protection (J2), OIDC bindings (J4), scanoria-scan digest', role: 'viewer' } },
  '/api/projects/{id}/ci/pr': { post: { summary: 'Open the integration pull request now (J2), or again after it was closed or failed; one active request per project; the appliance never merges it', role: 'operator' } },
  '/api/projects/{id}/ci/protection': { post: { summary: 'Apply (through the forge API) or decline the proposed branch protection (J2): human administrator session only, explicit confirmation of the exact rule; a missing forge permission is reported in the request detail', role: 'admin', body: 'ProtectionDecision' } },
  '/api/projects/{id}/ci/protection-request': { post: { summary: 'Propose the branch protection rule again, without applying it', role: 'operator' } },
  '/api/projects/{id}/ci/settings': { patch: { summary: 'Autonomous chain checkbox (J16), used by deployment; audited', role: 'admin', body: 'CiSettings' } },
  '/api/projects/{id}/ci/bindings': { post: { summary: 'Bind a forge repository to this project for CI OIDC tokens (J4), with allowed ref patterns (refs/heads/main and refs/tags/* by default); 409 E_EXISTS', role: 'admin', body: 'OidcBindingCreate', status: 201 } },
  '/api/projects/{id}/ci/bindings/{binding}': {
    patch: { summary: 'Change the ref patterns of an OIDC binding, or reset its pinned repository id', role: 'admin', body: 'OidcBindingPatch' },
    delete: { summary: 'Remove an OIDC binding: tokens of that repository are refused at once', role: 'admin', status: 204 },
  },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function ciSchemas(): Record<string, Record<string, unknown>> {
  return {
    OidcIssuerCreate: json(issuerCreateSchema),
    OidcIssuerPatch: json(issuerPatchSchema),
    OidcBindingCreate: json(bindingCreateSchema),
    OidcBindingPatch: json(bindingPatchSchema),
    ProtectionDecision: json(protectionDecisionSchema),
    CiSettings: json(ciSettingsSchema),
  }
}
