// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Jetons d'API par projet pour la CI (ARCHITECTURE § 12.8). Le jeton « scn_ »
// + 40 caractères alphanumériques n'est montré qu'une fois ; la base ne garde
// que son empreinte SHA-256 et son préfixe (8 caractères).

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Queryable } from '../utils/db'
import { API_TOKEN_RE } from '#shared/analysis'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
export const TOKEN_SCOPES = ['scan:create', 'scan:read'] as const
export type TokenScope = (typeof TOKEN_SCOPES)[number]

/** 40 caractères tirés sans biais (rejet des octets ≥ 248). */
export function generateToken(): string {
  let out = ''
  while (out.length < 40) {
    for (const b of randomBytes(64)) {
      if (b >= 248) continue
      out += ALPHABET[b % 62]
      if (out.length === 40) break
    }
  }
  return `scn_${out}`
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

export function tokenPrefix(token: string): string {
  return token.slice(0, 8)
}

export interface ApiTokenRow {
  id: string
  project_id: string
  name: string
  prefix: string
  scopes: string[]
  created_by: string | null
  created_by_username: string | null
  created_at: string
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

const COLUMNS = `t.id, t.project_id, t.name, t.prefix, t.scopes, t.created_by::text,
  u.username AS created_by_username,
  to_char(t.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
  to_char(t.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS expires_at,
  to_char(t.last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_used_at,
  to_char(t.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at`

export async function createApiToken(db: Queryable, p: { projectId: string, name: string, expiresInDays: number | null, createdBy: number }): Promise<{ token: string, row: ApiTokenRow }> {
  const token = generateToken()
  const res = await db.query<{ id: string }>(
    `INSERT INTO api_tokens (project_id, name, token_hash, prefix, created_by, expires_at)
     VALUES ($1, $2, $3, $4, $5, CASE WHEN $6::int IS NULL THEN NULL ELSE now() + make_interval(days => $6::int) END)
     RETURNING id`,
    [p.projectId, p.name, hashToken(token), tokenPrefix(token), p.createdBy, p.expiresInDays],
  )
  const row = await getApiToken(db, p.projectId, res.rows[0]!.id)
  return { token, row: row! }
}

export async function listApiTokens(db: Queryable, projectId: string): Promise<ApiTokenRow[]> {
  const res = await db.query<ApiTokenRow>(
    `SELECT ${COLUMNS} FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
      WHERE t.project_id = $1 ORDER BY t.revoked_at IS NOT NULL, t.created_at DESC`,
    [projectId],
  )
  return res.rows
}

export async function getApiToken(db: Queryable, projectId: string, id: string): Promise<ApiTokenRow | null> {
  const res = await db.query<ApiTokenRow>(
    `SELECT ${COLUMNS} FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
      WHERE t.project_id = $1 AND t.id = $2`,
    [projectId, id],
  )
  return res.rows[0] ?? null
}

export async function revokeApiToken(db: Queryable, projectId: string, id: string): Promise<boolean> {
  const res = await db.query(
    'UPDATE api_tokens SET revoked_at = now() WHERE project_id = $1 AND id = $2 AND revoked_at IS NULL',
    [projectId, id],
  )
  return (res.rowCount ?? 0) > 0
}

export type TokenCheck
  = | { ok: true, token: { id: string, projectId: string, scopes: string[], prefix: string } }
    | { ok: false, code: 'E_TOKEN_INVALID' | 'E_TOKEN_REVOKED' | 'E_TOKEN_EXPIRED' }

/**
 * Vérifie un jeton présenté. La recherche se fait par empreinte (index unique),
 * puis l'empreinte trouvée est recomparée en temps constant.
 */
export async function verifyApiToken(db: Queryable, presented: string): Promise<TokenCheck> {
  if (!API_TOKEN_RE.test(presented)) return { ok: false, code: 'E_TOKEN_INVALID' }
  const hash = hashToken(presented)
  const res = await db.query<{ id: string, project_id: string, token_hash: string, scopes: string[], prefix: string, revoked: boolean, expired: boolean, archived: boolean }>(
    `SELECT t.id, t.project_id, t.token_hash, t.scopes, t.prefix,
            t.revoked_at IS NOT NULL AS revoked,
            (t.expires_at IS NOT NULL AND t.expires_at <= now()) AS expired,
            p.archived_at IS NOT NULL AS archived
       FROM api_tokens t JOIN projects p ON p.id = t.project_id
      WHERE t.token_hash = $1`,
    [hash],
  )
  const row = res.rows[0]
  if (!row || !timingSafeEqual(Buffer.from(row.token_hash, 'hex'), Buffer.from(hash, 'hex'))) {
    return { ok: false, code: 'E_TOKEN_INVALID' }
  }
  if (row.revoked || row.archived) return { ok: false, code: 'E_TOKEN_REVOKED' }
  if (row.expired) return { ok: false, code: 'E_TOKEN_EXPIRED' }
  // last_used_at : au plus une écriture par minute et par jeton.
  await db.query(
    `UPDATE api_tokens SET last_used_at = now()
      WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')`,
    [row.id],
  )
  return { ok: true, token: { id: row.id, projectId: row.project_id, scopes: row.scopes, prefix: row.prefix } }
}
