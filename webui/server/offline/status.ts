// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Hors ligne (0.6, chantier A, CLAUDE.md § 9) : lecture de l'état publié par
// le helper (/var/lib/scanoria/offline/status.json, schéma offline-status) et
// des tables trusted_keys et offline_bundles. La console ne lit jamais la clé
// privée de l'appliance : seuls la clé publique et son empreinte sont publiés.

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import type { Queryable } from '../utils/db'
import { KEY_FINGERPRINT_RE, MODULE_ID_RE, PUBLIC_KEY_B64_RE, TIMESTAMP_RE } from '#shared/schemas'

const fp = z.string().regex(KEY_FINGERPRINT_RE)
const ts = z.string().regex(TIMESTAMP_RE)
const moduleId = z.string().regex(MODULE_ID_RE)

/** Nom d'un lot exporté sous /var/lib/scanoria/bundles. */
export const BUNDLE_NAME_RE = /^scanoria-bundle-[0-9]{8}T[0-9]{6}Z\.tar$/

export const offlineStatusSchema = z.object({
  version: z.literal(1),
  updated_at: ts,
  appliance_key: z.object({ public_key: z.string().regex(PUBLIC_KEY_B64_RE), fingerprint: fp }).nullable(),
  trusted_keys: z.array(fp).max(32),
  bundles: z.array(z.object({
    name: z.string().regex(BUNDLE_NAME_RE),
    created_at: ts,
    size_bytes: z.number().int().min(0),
    sha256: fp,
    signer_fingerprint: fp,
    modules: z.array(moduleId).max(128),
    feeds: z.array(z.object({ id: moduleId, updated_at: ts })).max(64).optional(),
    images: z.array(moduleId).max(128).optional(),
    catalog_version: z.number().int().nullable().optional(),
    scheduled: z.boolean().nullable().optional(),
  })).max(16),
  last_import: z.object({
    at: ts,
    sha256: fp,
    signer_fingerprint: fp,
    created_at: ts,
    catalog_version: z.number().int(),
    feeds: z.array(moduleId).max(64),
    images: z.array(moduleId).max(128),
  }).nullable(),
  mirror: z.object({
    url: z.string().max(300),
    addresses: z.array(z.string().max(45)).max(16),
    fingerprint: fp,
    pinned_at: ts,
    ca: z.boolean(),
    last_check: z.object({
      checked_at: ts,
      url: z.string().max(300).nullable().optional(),
      manifest: z.object({
        created_at: ts,
        catalog_version: z.number().int(),
        feeds: z.array(z.object({ id: moduleId, updated_at: ts })).max(64),
        images: z.array(moduleId).max(128),
      }).nullable(),
      error: z.string().max(2000).nullable(),
    }).nullable(),
  }).nullable(),
  publication: z.object({
    url: z.string().max(300).nullable(),
    created_at: ts.nullable().optional(),
    catalog_version: z.number().int().nullable().optional(),
    feeds: z.array(moduleId).max(64),
    images: z.array(moduleId).max(128),
  }).nullable(),
  schedule: z.object({
    enabled: z.boolean(),
    every_days: z.number().int().min(1).max(31),
    keep: z.number().int().min(1).max(10),
    modules: z.array(moduleId).max(64),
    last_run_at: ts.nullable(),
  }),
  dtrack: z.object({
    synced_at: ts.nullable().optional(),
    configured_at: ts.nullable().optional(),
    configure_error: z.string().max(500).nullable().optional(),
    sources: z.array(z.object({
      id: z.string().max(32),
      available: z.boolean(),
      ecosystems: z.array(z.string().max(64)).max(64),
      updated_at: ts.nullable(),
      reason: z.string().max(64).nullable(),
    })).max(16),
    gaps: z.array(z.object({ id: z.string().max(32), reason: z.string().max(64) })).max(16),
  }).nullable(),
})
export type OfflineStatus = z.infer<typeof offlineStatusSchema>

/** État publié, ou null (pas encore publié, illisible ou non conforme). */
export async function readOfflineStatus(path: string): Promise<OfflineStatus | null> {
  try {
    const buf = await readFile(path)
    if (buf.length > 1024 * 1024) return null
    const parsed = offlineStatusSchema.safeParse(JSON.parse(buf.toString('utf8')))
    return parsed.success ? parsed.data : null
  }
  catch {
    return null
  }
}

/** Empreinte (SHA-256 hexadécimal) d'une clé publique Ed25519 brute en base64 ; null si invalide. */
export function keyFingerprint(publicKey: string): string | null {
  if (!PUBLIC_KEY_B64_RE.test(publicKey)) return null
  const raw = Buffer.from(publicKey, 'base64')
  if (raw.length !== 32 || raw.toString('base64') !== publicKey) return null
  return createHash('sha256').update(raw).digest('hex')
}

export interface TrustedKeyRow {
  id: string
  label: string
  purpose: string
  public_key: string
  fingerprint: string
  added_at: string
  added_by_username: string | null
  revoked_at: string | null
}

export async function listTrustedKeys(db: Queryable): Promise<TrustedKeyRow[]> {
  const r = await db.query<TrustedKeyRow>(
    `SELECT k.id, k.label, k.purpose, k.public_key, k.fingerprint, k.added_at, u.username AS added_by_username, k.revoked_at
       FROM trusted_keys k LEFT JOIN users u ON u.id = k.added_by
      ORDER BY k.revoked_at IS NOT NULL, k.added_at DESC
      LIMIT 100`)
  return r.rows
}

export interface BundleRow {
  id: string
  direction: 'export' | 'import'
  status: string
  contents: Record<string, unknown>
  size_bytes: string | null
  sha256: string | null
  signer_fingerprint: string | null
  request_id: string | null
  error: unknown
  requested_by_username: string | null
  created_at: string
  finished_at: string | null
}

export async function listBundles(db: Queryable): Promise<BundleRow[]> {
  const r = await db.query<BundleRow>(
    `SELECT b.id, b.direction, b.status, b.contents, b.size_bytes::text, b.sha256, b.signer_fingerprint,
            b.request_id, b.error, u.username AS requested_by_username, b.created_at, b.finished_at
       FROM offline_bundles b LEFT JOIN users u ON u.id = b.requested_by
      ORDER BY b.created_at DESC
      LIMIT 50`)
  return r.rows
}
