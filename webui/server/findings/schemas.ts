// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Entrées de l'API des résultats, des exceptions et des gravités (zod).

import { z } from 'zod'
import { CATEGORIES, FINDING_STATUSES, SEVERITIES, SECRET_STATES } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import { isValidDay } from './exceptions'

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const uuid = z.string().regex(UUID_RE)
const bool = z.enum(['true', 'false', '1', '0']).transform(v => v === 'true' || v === '1')
/** Liste « a,b » ou valeur répétée dans la requête. */
const list = <T extends readonly [string, ...string[]]>(values: T) =>
  z.union([z.string(), z.array(z.string())])
    .transform(v => (Array.isArray(v) ? v : v.split(',')).map(s => s.trim()).filter(Boolean))
    .pipe(z.array(z.enum(values)).max(values.length))

export const findingQuerySchema = z.strictObject({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
  project_id: uuid.optional(),
  scan_id: uuid.optional(),
  tool: z.string().regex(MODULE_ID_RE).optional(),
  severity: list(SEVERITIES).optional(),
  category: z.enum(CATEGORIES).optional(),
  status: list(FINDING_STATUSES).optional(),
  is_new: bool.optional(),
  secret: bool.optional(),
  malicious: bool.optional(),
  q: z.string().trim().min(1).max(200).optional(),
  // 0.5 : EPSS minimal et KEV (H3), regroupement des résultats recoupés (F16).
  epss_min: z.coerce.number().min(0).max(1).optional(),
  kev: bool.optional(),
  grouped: bool.optional(),
  // 0.6 (J6) : origine du résultat, module de l'appliance ou outil externe.
  origin: z.enum(['module', 'external']).optional(),
})

const day = z.string().refine(isValidDay)

export const statusChangeSchema = z.discriminatedUnion('status', [
  z.strictObject({ status: z.literal('new'), reason: z.string().trim().max(2000).optional() }),
  z.strictObject({ status: z.literal('confirmed'), reason: z.string().trim().max(2000).optional() }),
  z.strictObject({ status: z.literal('false-positive'), reason: z.string().trim().min(3).max(2000) }),
  z.strictObject({ status: z.literal('accepted'), reason: z.string().trim().min(3).max(2000), until: day }),
])

export const secretStateSchema = z.strictObject({ state: z.enum(SECRET_STATES) })

export const exceptionQuerySchema = z.strictObject({
  project_id: uuid,
  all: bool.optional(),
})

export const severityUpdateSchema = z.strictObject({
  module_id: z.string().regex(MODULE_ID_RE),
  native: z.string().min(1).max(64),
  /** null : retour à la valeur d'origine. */
  severity: z.enum(SEVERITIES).nullable(),
})

export function uuidParam(raw: string | undefined): string | null {
  return raw && UUID_RE.test(raw) ? raw : null
}
