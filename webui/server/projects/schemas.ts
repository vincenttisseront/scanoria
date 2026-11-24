// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Corps des requêtes des forges et des projets (validation zod stricte).

import { z } from 'zod'
import { FORGE_KINDS, SCHEDULES } from '#shared/analysis'
import { isSafeRef } from '../forges/types'

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
/** Jeton : ASCII imprimable sans espace (jamais renvoyé, jamais journalisé). */
export const tokenSchema = z.string().min(1).max(4096).regex(/^[\x21-\x7e]+$/)
const username = z.string().min(1).max(255).regex(/^[^:\s]+$/)
const privateKey = z.string().max(16_384).regex(/^-{5}BEGIN OPENSSH PRIVATE KEY-{5}\r?\n/)
const branch = z.string().min(1).max(255).refine(isSafeRef)
const fullName = z.string().min(3).max(300).regex(/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)+$/)
const name = z.string().trim().min(1).max(200)

export const forgeCreateSchema = z.strictObject({
  kind: z.enum(FORGE_KINDS),
  name: z.string().trim().min(1).max(100),
  base_url: z.string().min(9).max(512),
  token: tokenSchema.optional(),
  discovery: z.boolean().default(true),
})

export const forgeUpdateSchema = z.strictObject({
  name: z.string().trim().min(1).max(100).optional(),
  token: tokenSchema.nullable().optional(),
  discovery: z.boolean().optional(),
})

const common = {
  name: name.optional(),
  tracked_branches: z.array(branch).max(20).optional(),
  schedule: z.enum(SCHEDULES).optional(),
  ai_opt_out: z.boolean().optional(),
}

export const projectCreateSchema = z.discriminatedUnion('source', [
  z.strictObject({ source: z.literal('forge'), forge_id: uuid, repo: fullName, ...common }),
  z.strictObject({
    source: z.literal('git'),
    url: z.string().min(8).max(1024),
    auth: z.discriminatedUnion('kind', [
      z.strictObject({ kind: z.literal('none') }),
      z.strictObject({ kind: z.literal('token'), token: tokenSchema, username: username.optional() }),
      z.strictObject({ kind: z.literal('ssh-key'), private_key: privateKey, known_hosts: z.string().min(1).max(16_384) }),
    ]).default({ kind: 'none' }),
    default_branch: branch.optional(),
    ...common,
  }),
  z.strictObject({ source: z.literal('archive'), upload_id: uuid, name, schedule: z.enum(SCHEDULES).optional(), ai_opt_out: z.boolean().optional() }),
])
export type ProjectCreateBody = z.infer<typeof projectCreateSchema>

export const projectPreviewSchema = z.union([
  z.strictObject({ forge_id: uuid, repo: fullName }),
  z.strictObject({ url: z.string().min(8).max(1024) }),
])

export const hostKeysSchema = z.strictObject({ url: z.string().min(8).max(1024) })

export const projectUpdateSchema = z.strictObject({
  ...common,
  profile_id: uuid.optional(),
  gate_id: uuid.optional(),
  /** Remplace le jeton (URL HTTPS libre) ; null le retire. */
  token: tokenSchema.nullable().optional(),
  /** Nouvelle clé SSH et clés d'hôte confirmées (URL SSH). */
  ssh: z.strictObject({ private_key: privateKey.optional(), known_hosts: z.string().min(1).max(16_384) }).optional(),
  /** Nouvelle archive téléversée (projet archive). */
  upload_id: uuid.optional(),
})

export const archiveSchema = z.strictObject({ archived: z.boolean() })
export const deleteSchema = z.strictObject({ confirm: z.string().min(1).max(64) })
export const listQuerySchema = z.strictObject({ archived: z.enum(['0', '1', 'true', 'false']).optional(), forge_id: uuid.optional() })
