// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// État de vigilance publié par le helper (0.6, chantier B) :
// /var/lib/scanoria/vigilance/state.json (root:scanoria 0640), relu à chaque
// appel et validé sans confiance. Images retenues (versions figées G6,
// candidates F13) et dernier relevé des SBOM de l'appliance (F19).

import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import { MODULE_ID_RE, MODULE_VERSION_RE, TIMESTAMP_RE, UUID_V4_RE } from '#shared/schemas'

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/)
const ts = z.string().regex(TIMESTAMP_RE)
const err = z.object({ code: z.string().max(64), message: z.string().max(500) }).nullable().optional()

export const retainedSchema = z.object({
  module: z.string().regex(MODULE_ID_RE),
  version: z.string().regex(MODULE_VERSION_RE),
  image_digest: digest,
  kind: z.enum(['pin', 'trial']),
  trial_id: z.string().regex(UUID_V4_RE).nullable().optional(),
  retained_at: ts.nullable().optional(),
})
export type RetainedEntry = z.infer<typeof retainedSchema>

export const selfSubjectSchema = z.object({
  subject: z.string().regex(/^(console|module:[a-z0-9][a-z0-9-]{1,40})$/),
  version: z.string().max(64).nullable().optional(),
  image_digest: digest.nullable().optional(),
  components: z.number().int().min(0).default(0),
  sbom_sha256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
  tools: z.array(z.object({
    id: z.string().regex(MODULE_ID_RE),
    version: z.string().max(64),
    ok: z.boolean(),
    output: z.string().regex(/^[a-z0-9.-]{1,60}\/[a-z0-9-]{1,41}\.sarif$/).nullable().optional(),
    error: err,
  })).max(8).default([]),
  error: err,
})
export type SelfSubject = z.infer<typeof selfSubjectSchema>

export const selfStatusSchema = z.object({
  version: z.literal(1),
  at: ts,
  subjects: z.array(selfSubjectSchema).max(200),
  gaps: z.array(z.enum(['syft-missing', 'matcher-missing', 'console-sbom-missing', 'timeout'])).max(8),
})
export type SelfStatus = z.infer<typeof selfStatusSchema>

export interface VigilanceState {
  available: boolean
  updated_at: string | null
  retained: RetainedEntry[]
  self_sbom: SelfStatus | null
}

export async function readVigilanceState(path: string): Promise<VigilanceState> {
  let raw: unknown
  try {
    const buf = await readFile(path)
    if (buf.length > 1024 * 1024) throw new Error('too large')
    raw = JSON.parse(buf.toString('utf8'))
  }
  catch {
    return { available: false, updated_at: null, retained: [], self_sbom: null }
  }
  const doc = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const retained = (Array.isArray(doc.retained) ? doc.retained.slice(0, 400) : [])
    .map(r => retainedSchema.safeParse(r)).filter(r => r.success).map(r => r.data)
  const self = selfStatusSchema.safeParse(doc.self_sbom)
  return {
    available: doc.version === 1,
    updated_at: typeof doc.updated_at === 'string' && TIMESTAMP_RE.test(doc.updated_at) ? doc.updated_at : null,
    retained,
    self_sbom: self.success ? self.data : null,
  }
}
