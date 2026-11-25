// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI du tri (0.7, chantier B : F4, F5/J15, F6),
// repris par server/api/openapi.json.get.ts. Les schémas des corps sont
// générés depuis les schémas zod qui valident réellement les requêtes.

import { z } from 'zod'
import { decisionSchema, exceptionCreateSchema } from './exceptions'
import { exceptionRequestSchema } from './exceptions-http'
import { triageRuleSchema } from './triage-rules'
import { ownerMappingSchema } from './owners'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number, token?: boolean }

export const TRIAGE_OPS: Record<string, Record<string, Op>> = {
  '/api/exceptions': {
    get: { summary: 'Project exceptions (query project_id; all=true includes refused, expired and revoked). Each item carries status (requested, approved, refused), requester, decision and expiry flags', role: 'viewer' },
    post: { summary: 'Request a dated exception (F5): status requested, never effective until an administrator approves it; at most 366 days; 409 E_MALICIOUS for MAL- advisories (H4), 409 E_LOCKED against a profile lock (G8)', role: 'operator', body: 'ExceptionCreate', status: 201 },
  },
  '/api/exceptions/{id}': {
    get: { summary: 'One exception with its request and decision history', role: 'viewer' },
    delete: { summary: 'Withdraw a request or revoke an approved exception (history kept); verdicts re-evaluated without rescanning', role: 'operator' },
  },
  '/api/exceptions/pending': { get: { summary: 'Pending requests, all projects; each item carries cannot_decide (not-admin, not-human, inactive, requester, commit-author) for the caller', role: 'admin' } },
  '/api/exceptions/pending-count': { get: { summary: 'Number of pending requests (0 for non-administrators), for the navigation counter', role: 'viewer' } },
  '/api/exceptions/expiring': { get: { summary: 'Approved exceptions expiring within 14 days (query project_id optional)', role: 'viewer' } },
  '/api/exceptions/{id}/decision': { post: { summary: 'Approve or refuse a request (J15): human administrator session only, never an API token; the requester and the authors of the scanned commit cannot decide (403 E_DECIDER_NOT_ALLOWED with reason); 409 E_NOT_PENDING, E_EXPIRED, E_MALICIOUS, E_LOCKED. After an approval the latest verdicts of the project are re-evaluated without rescanning → reevaluated[]', role: 'admin', body: 'ExceptionDecision' } },
  '/api/projects/{id}/exception-requests': { post: { summary: 'Request an exception from CI (J15): project API token (scope scan:create, non-human identity: it requests, never decides) or operator session; commit_authors are excluded from the decision', role: 'operator', body: 'ExceptionRequest', status: 201, token: true } },
  '/api/triage-rules': {
    get: { summary: 'Bulk triage rules (F4), query project_id, all=true includes expired and revoked', role: 'viewer' },
    post: { summary: 'Save a triage rule and apply it to matching new findings (reason and end date required; accepted and global rules need admin; never on malicious packages)', role: 'operator', body: 'TriageRule', status: 201 },
  },
  '/api/triage-rules/simulate': { post: { summary: 'Simulate a triage rule: findings that would be affected, nothing written', role: 'operator', body: 'TriageRule' } },
  '/api/triage-rules/{id}': { delete: { summary: 'Revoke a triage rule: findings it set and nobody changed since become new again', role: 'operator' } },
  '/api/triage-rules/proposals': { get: { summary: 'Rules proposed from AI pre-triage (I3) for a project (query project_id); enabled false without connector. Saving stays a human action', role: 'operator' } },
  '/api/owner-mappings': {
    get: { summary: 'CODEOWNERS owner to console account mappings (F6)', role: 'viewer' },
    post: { summary: 'Add a mapping (project_id null for all projects)', role: 'admin', body: 'OwnerMapping', status: 201 },
    delete: { summary: 'Remove a mapping', role: 'admin', body: 'OwnerMapping' },
  },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function triageSchemas(): Record<string, Record<string, unknown>> {
  return {
    ExceptionCreate: json(exceptionCreateSchema),
    ExceptionRequest: json(exceptionRequestSchema),
    ExceptionDecision: json(decisionSchema),
    TriageRule: json(triageRuleSchema),
    OwnerMapping: json(ownerMappingSchema),
  }
}
