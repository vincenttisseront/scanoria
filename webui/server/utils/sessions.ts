// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sessions : jeton aléatoire de 32 octets dans un cookie httpOnly, Secure,
// SameSite=Strict ; seule son empreinte SHA-256 est stockée. Le jeton CSRF
// est dérivé du jeton de session (HMAC), remis au client par /api/auth/session
// et exigé dans l'en-tête X-CSRF-Token de toute requête qui modifie.

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Queryable } from './db'
import type { AuthSettings } from './settings'
import type { Role } from '#shared/schemas'

export const SESSION_COOKIE = '__Host-scanoria_session'
export const CSRF_HEADER = 'x-csrf-token'
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/

export function newSessionToken(): string {
  return randomBytes(32).toString('base64url')
}

export function isWellFormedToken(token: string | undefined): token is string {
  return typeof token === 'string' && TOKEN_RE.test(token)
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

export function csrfTokenFor(sessionToken: string): string {
  return createHmac('sha256', sessionToken).update('scanoria-csrf-v1').digest('base64url')
}

export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a)
  const bb = Buffer.from(b)
  return ba.length === bb.length && timingSafeEqual(ba, bb)
}

export interface SessionUser {
  id: number
  username: string
  displayName: string | null
  role: Role
  locale: 'fr' | 'en'
  mustChangePassword: boolean
}

export interface ResolvedSession {
  tokenHash: string
  expiresAt: Date
  user: SessionUser
}

export async function createSession(
  db: Queryable,
  userId: number,
  settings: AuthSettings,
  meta: { ip?: string | null, userAgent?: string | null },
): Promise<{ token: string, expiresAt: Date }> {
  const token = newSessionToken()
  const { rows } = await db.query<{ expires_at: Date }>(
    `INSERT INTO sessions (token_hash, user_id, expires_at, ip, user_agent)
     VALUES ($1, $2, now() + make_interval(hours => $3), $4, $5)
     RETURNING expires_at`,
    [hashToken(token), userId, settings.sessionMaxHours, meta.ip ?? null, meta.userAgent?.slice(0, 512) ?? null],
  )
  return { token, expiresAt: rows[0]!.expires_at }
}

interface SessionJoinRow {
  expires_at: Date
  touch: boolean
  id: string
  username: string
  display_name: string | null
  role: Role
  locale: 'fr' | 'en'
  must_change_password: boolean
}

/** Session valide (non révoquée, non expirée, active récemment, compte actif) ou null. */
export async function resolveSession(db: Queryable, token: string, settings: AuthSettings): Promise<ResolvedSession | null> {
  if (!isWellFormedToken(token)) return null
  const tokenHash = hashToken(token)
  const { rows } = await db.query<SessionJoinRow>(
    `SELECT s.expires_at, s.last_seen_at < now() - interval '1 minute' AS touch,
            u.id::text, u.username, u.display_name, u.role, u.locale, u.must_change_password
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
        AND s.last_seen_at > now() - make_interval(mins => $2) AND u.is_active`,
    [tokenHash, settings.sessionIdleMinutes],
  )
  const row = rows[0]
  if (!row) return null
  if (row.touch) {
    await db.query('UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1', [tokenHash])
  }
  return {
    tokenHash,
    expiresAt: row.expires_at,
    user: {
      id: Number(row.id),
      username: row.username,
      displayName: row.display_name,
      role: row.role,
      locale: row.locale,
      mustChangePassword: row.must_change_password,
    },
  }
}

export async function revokeSession(db: Queryable, tokenHash: string): Promise<void> {
  await db.query('UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL', [tokenHash])
}

export async function revokeUserSessions(db: Queryable, userId: number, exceptTokenHash?: string): Promise<number> {
  const { rowCount } = await db.query(
    `UPDATE sessions SET revoked_at = now()
      WHERE user_id = $1 AND revoked_at IS NULL AND ($2::text IS NULL OR token_hash <> $2)`,
    [userId, exceptTokenHash ?? null],
  )
  return rowCount ?? 0
}

export async function purgeSessions(db: Queryable): Promise<void> {
  await db.query(
    `DELETE FROM sessions WHERE expires_at < now() - interval '7 days'
        OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '7 days')`,
  )
}
