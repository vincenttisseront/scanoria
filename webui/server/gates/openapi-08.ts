// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chemins et schémas OpenAPI du chantier B de la 0.8 (F9 simulateur, I19
// seuils suggérés, H7 VEX), repris par server/api/openapi.json.get.ts. Les
// corps sont générés depuis les schémas zod qui valident réellement les
// requêtes.

import { z } from 'zod'
import { simulationRequestSchema } from './simulate'
import { vexImportSchema } from '../vex/vex'

type Role = 'public' | 'viewer' | 'operator' | 'admin'
interface Op { summary: string, role: Role, body?: string, status?: number, token?: boolean }

export const GATE_VEX_OPS: Record<string, Record<string, Op>> = {
  '/api/gates/simulations': {
    post: { summary: 'Simulate candidate gate rules on the history of a gate or a project (F9): each scan is replayed with its frozen plan (G11) and the exceptions as of its date; nothing but the simulation is written. 201 with status done for a short history, 202 with status pending otherwise (follow GET /api/gates/simulations/{id}). 429 E_RATE_LIMITED when too many background simulations run. Saving stays PATCH /api/gates/{id}', role: 'operator', body: 'GateSimulation', status: 201 },
  },
  '/api/gates/simulations/{id}': { get: { summary: 'One simulation: status (pending, done, error), origin (manual, ai) and result (blocked, unblocked and unchanged scans and releases, responsible rules, scans concerned)', role: 'viewer' } },
  '/api/gates/projects/{id}/suggestion/simulate': { post: { summary: 'Simulate the latest AI threshold suggestion of a project (I19), once (origin ai); 404 without connector, without suggestion or for an « ai opt-out » project; 429 E_RATE_LIMITED when background simulations are busy', role: 'operator' } },
  '/api/gates/suggestions/{id}': { get: { summary: 'Candidate rules of an AI threshold suggestion (I19) to prefill the gate page, with model and digest', role: 'viewer' } },
  '/api/vex/projects/{id}/export': { get: { summary: 'Canonical VEX document of a project (H7): ?format=openvex (0.2, default) or cyclonedx (1.6); ?scan_id restricts to the vulnerabilities of a scan. Header x-scanoria-sha256 carries the document hash. Audited', role: 'viewer' } },
  '/api/vex/projects/{id}/statements': { get: { summary: 'VEX statements in force for a project (approved exceptions with a VEX status, imported statements) and the hash of the canonical document', role: 'viewer' } },
  '/api/vex/projects/{id}/import': { post: { summary: 'Strict import of an OpenVEX 0.2 or CycloneDX VEX document (H7). dry_run (default true) previews the effects. not_affected and fixed become exception REQUESTS (requested_via tool-import), never approvals; other statuses are kept for information; never for MAL- advisories (H4) or against a profile lock (G8). 400 E_VALIDATION with reason for a malformed document. Audited', role: 'operator', body: 'VexImport' } },
}

const json = (s: z.ZodType) => z.toJSONSchema(s, { io: 'input', unrepresentable: 'any' }) as Record<string, unknown>

export function gateVexSchemas(): Record<string, Record<string, unknown>> {
  return {
    GateSimulation: json(simulationRequestSchema),
    VexImport: json(vexImportSchema),
  }
}
