// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Schémas zod des routes de l'intégration CI (0.8, chantier C : J2, J3, J4).

import { z } from 'zod'
import { REF_PATTERN_RE } from './jwt'

const refPatterns = z.array(z.string().regex(REF_PATTERN_RE).max(201)).min(1).max(20)

export const issuerCreateSchema = z.object({
  kind: z.enum(['github', 'gitlab', 'forgejo']),
  issuer: z.string().min(9).max(255).regex(/^https:\/\/[^\s/?#@]+(\/[^\s?#@]*)?$/),
  audience: z.string().min(1).max(255).regex(/^[\x21-\x7e]+$/).optional(),
}).strict()

export const issuerPatchSchema = z.object({ enabled: z.boolean() }).strict()

export const bindingCreateSchema = z.object({
  issuer_id: z.uuid(),
  // Segments « . » et « .. » refusés, comme dans les revendications (jwt.ts).
  repository: z.string().min(3).max(255).regex(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+){1,9}$/).refine(r => !r.split('/').some(s => s === '.' || s === '..')),
  ref_patterns: refPatterns.optional(),
}).strict()

// Motifs de ref, ou réinitialisation de l'identifiant épinglé (dépôt légitimement recréé).
export const bindingPatchSchema = z.object({ ref_patterns: refPatterns.optional(), reset_repository_id: z.literal(true).optional() }).strict()
  .refine(b => b.ref_patterns !== undefined || b.reset_repository_id === true)

export const protectionDecisionSchema = z.object({
  request_id: z.uuid(),
  action: z.enum(['apply', 'decline']),
  include_release_gate: z.boolean().optional(),
  /** Confirmation explicite de la modale (règle exacte montrée). */
  confirm: z.literal(true),
}).strict()

export const ciSettingsSchema = z.object({ autonomous_chain: z.boolean() }).strict()

export const templateQuerySchema = z.object({
  file: z.string().min(1).max(100),
  project: z.uuid().optional(),
}).strict()
