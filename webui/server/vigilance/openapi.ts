// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI de la vigilance (0.6, chantier B : F19, G14,
// F13, G6), repris par server/api/openapi.json.get.ts. Les schémas des corps
// sont générés depuis les schémas zod qui valident réellement les requêtes.

import { z } from 'zod'
import { canariesBodySchema, pinBodySchema, trialBodySchema } from './api'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number }

export const VIGILANCE_OPS: Record<string, Record<string, Op>> = {
  '/api/vigilance': { get: { summary: 'Appliance vigilance: vulnerabilities of the console and installed module images (F19) with "update available" alerts, latest canaries (G14), retained images, trials (F13)', role: 'viewer' } },
  '/api/vigilance/self-vulns': { get: { summary: 'Open vulnerabilities of one appliance subject (query subject=console or module:<id>)', role: 'viewer' } },
  '/api/vigilance/self-sbom': { post: { summary: 'Request self-sbom now (otherwise daily): SBOM of the installed images, compared with Grype and OSV-Scanner', role: 'admin', status: 202 } },
  '/api/vigilance/canaries': { post: { summary: 'Request run-canaries now (otherwise nightly): F12 testbed of every installed scanner, or of ids', role: 'admin', body: 'CanariesRun', status: 202 } },
  '/api/catalog/modules/{id}/vigilance': { get: { summary: 'Canary history, trials and candidate versions, projects pinning a version, open vulnerabilities of a module', role: 'viewer' } },
  '/api/catalog/modules/{id}/trials': { post: { summary: 'Try a newer version of a scanner on its latest scans, with no side effect (F13); 409 E_PRECONDITION with reason', role: 'admin', body: 'TrialStart', status: 202 } },
  '/api/catalog/modules/{id}/trials/{trial}/adopt': { post: { summary: 'Adopt the tried version: a normal update-module (backup, health, rollback)', role: 'admin', status: 202 } },
  '/api/catalog/modules/{id}/trials/{trial}/abandon': { post: { summary: 'Abandon a trial: queued trial scans cancelled, candidate image removed', role: 'admin', status: 202 } },
  '/api/projects/{id}/pins': { get: { summary: 'Module versions pinned by the project (G6) with warnings (retired, vulnerable, missing), and modules that can be pinned', role: 'viewer' } },
  '/api/projects/{id}/pins/{module}': {
    put: { summary: 'Pin the installed version of a scanner for this project (reason required, audited)', role: 'admin', body: 'ModulePin' },
    delete: { summary: 'Unpin: the project follows the installed version again (audited)', role: 'admin' },
  },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function vigilanceSchemas(): Record<string, Record<string, unknown>> {
  return { CanariesRun: json(canariesBodySchema), TrialStart: json(trialBodySchema), ModulePin: json(pinBodySchema) }
}
