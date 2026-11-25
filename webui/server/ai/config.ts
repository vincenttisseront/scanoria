// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Configuration du connecteur IA (CLAUDE.md § 3.5) : adresse épinglée par le
// helper root (/etc/scanoria/ai.json, schemas/ai-endpoint.schema.json),
// contrôle horaire (/run/scanoria/ai-status.json) et réglages de la console
// (appliance_settings ai.*). Sans fichier ou fichier invalide : connecteur
// inactif (échec fermé).

import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import { isIP } from 'node:net'
import type { Queryable } from '../utils/db'

const TS_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$/

export const AiEndpoint = z.discriminatedUnion('enabled', [
  z.strictObject({ version: z.literal(1), enabled: z.literal(false) }),
  z.strictObject({
    version: z.literal(1),
    enabled: z.literal(true),
    url: z.string().max(300).regex(/^https?:\/\//),
    scheme: z.enum(['https', 'http']),
    host: z.string().min(1).max(253).regex(/^[a-z0-9.:-]+$/),
    port: z.int().min(1).max(65535),
    addresses: z.array(z.string().max(45).refine(a => isIP(a) !== 0 && !a.includes('%'))).min(1).max(8),
    insecure: z.boolean(),
    token: z.boolean(),
    ca: z.boolean(),
    /** false : certificat du serveur accepté sans vérification ; absent (fichier antérieur) : vérifié. */
    tls_verify: z.boolean().optional(),
    literal: z.boolean(),
    pinned_at: z.string().regex(TS_RE),
  }),
])
export type AiEndpoint = z.infer<typeof AiEndpoint>
export type ActiveEndpoint = Extract<AiEndpoint, { enabled: true }>

export const AiCheckStatus = z.strictObject({
  version: z.literal(1),
  checked_at: z.string().regex(TS_RE),
  enabled: z.boolean(),
  resolution: z.strictObject({
    pinned: z.array(z.string().max(45)).max(8),
    current: z.array(z.string().max(45)).max(8),
    changed: z.boolean(),
    error: z.string().regex(/^E_[A-Z_]+$/).nullable(),
  }).nullable(),
  candidate: z.strictObject({
    url: z.string().max(300).regex(/^https?:\/\//),
    version: z.string().max(64),
    addresses: z.array(z.string().max(45)).min(1).max(8),
    insecure: z.boolean(),
  }).nullable(),
})
export type AiCheckStatus = z.infer<typeof AiCheckStatus>

export const DISABLED: AiEndpoint = { version: 1, enabled: false }

export interface AiPaths {
  /** Copie lue par la console (helper : /etc/scanoria/ai.json). */
  endpointFile: string
  statusFile: string
}

export function aiPaths(env: NodeJS.ProcessEnv = process.env): AiPaths {
  return {
    endpointFile: env.NUXT_AI_ENDPOINT_FILE || '/etc/scanoria/ai.json',
    statusFile: env.NUXT_AI_STATUS_FILE || '/run/scanoria/ai-status.json',
  }
}

async function readJson(path: string, maxBytes = 65_536): Promise<unknown> {
  const buf = await readFile(path)
  if (buf.length > maxBytes) throw new Error('file too large')
  return JSON.parse(buf.toString('utf8'))
}

/** Connecteur épinglé ; DISABLED si absent, illisible ou non conforme. */
export async function loadEndpoint(path: string): Promise<AiEndpoint> {
  try {
    const parsed = AiEndpoint.safeParse(await readJson(path))
    return parsed.success ? parsed.data : DISABLED
  }
  catch {
    return DISABLED
  }
}

export async function loadCheckStatus(path: string): Promise<AiCheckStatus | null> {
  try {
    const parsed = AiCheckStatus.safeParse(await readJson(path))
    return parsed.success ? parsed.data : null
  }
  catch {
    return null
  }
}

/** Réglages de la console : choix de modèle forcé par tâche, jeton chiffré. */
export interface AiSettings {
  models: Record<string, string>
  tokenCredentialId: string | null
}

const ModelName = z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/)
export const ModelOverrides = z.record(z.string().regex(/^[a-z][a-z0-9-]{1,40}$/), ModelName)

export async function loadAiSettings(db: Queryable): Promise<AiSettings> {
  const { rows } = await db.query<{ key: string, value: unknown }>(
    `SELECT key, value FROM appliance_settings WHERE key IN ('ai.models', 'ai.token_credential_id')`,
  )
  const map = new Map(rows.map(r => [r.key, r.value]))
  const models = ModelOverrides.safeParse(map.get('ai.models') ?? {})
  const token = z.uuid().safeParse(map.get('ai.token_credential_id'))
  return { models: models.success ? models.data : {}, tokenCredentialId: token.success ? token.data : null }
}
