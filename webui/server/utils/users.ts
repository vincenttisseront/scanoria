// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Comptes locaux : lecture, création, modification, authentification avec
// verrouillage temporaire après N échecs (réglages auth.lockout_*).

import type { Queryable } from './db'
import type { AuthSettings } from './settings'
import { burnPasswordCheck, hashPassword, verifyPassword } from './password'
import type { Role } from '#shared/schemas'

export interface UserRow {
  id: string
  username: string
  display_name: string | null
  email: string | null
  role: Role
  auth_source: string
  must_change_password: boolean
  locale: 'fr' | 'en'
  is_active: boolean
  /** J15 (0.7) : « agent » ou « bot » demande, mais ne décide jamais une exception. */
  kind: 'human' | 'agent' | 'bot'
  locked_until: string | null
  last_login_at: string | null
  created_at: string
  updated_at: string
}

const ts = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS ${col}`
const USER_COLUMNS = `id::text, username, display_name, email, role, auth_source, must_change_password, locale,
  is_active, kind, ${ts('locked_until')}, ${ts('last_login_at')}, ${ts('created_at')}, ${ts('updated_at')}`

export async function listUsers(db: Queryable): Promise<UserRow[]> {
  const { rows } = await db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users ORDER BY username`)
  return rows
}

export async function getUser(db: Queryable, id: number): Promise<UserRow | null> {
  const { rows } = await db.query<UserRow>(`SELECT ${USER_COLUMNS} FROM users WHERE id = $1`, [id])
  return rows[0] ?? null
}

export async function countActiveAdmins(db: Queryable, excludeId?: number): Promise<number> {
  const { rows } = await db.query<{ n: string }>(
    `SELECT count(*) AS n FROM users WHERE role = 'admin' AND is_active AND ($1::bigint IS NULL OR id <> $1)`,
    [excludeId ?? null],
  )
  return Number(rows[0]?.n ?? 0)
}

export interface NewUser {
  username: string
  displayName?: string | null
  email?: string | null
  role: Role
  locale?: 'fr' | 'en'
  password?: string
  passwordHash?: string
  mustChangePassword?: boolean
}

export class UsernameTakenError extends Error {}

export async function createUser(db: Queryable, u: NewUser): Promise<UserRow> {
  const hash = u.passwordHash ?? (u.password ? await hashPassword(u.password) : null)
  if (!hash) throw new Error('password required')
  try {
    const { rows } = await db.query<UserRow>(
      `INSERT INTO users (username, display_name, email, role, locale, password_hash, must_change_password, password_changed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now())
       RETURNING ${USER_COLUMNS}`,
      [u.username, u.displayName ?? null, u.email ?? null, u.role, u.locale ?? 'fr', hash, u.mustChangePassword ?? false],
    )
    return rows[0]!
  }
  catch (err) {
    if ((err as { code?: string }).code === '23505') throw new UsernameTakenError()
    throw err
  }
}

export interface UserPatch {
  display_name?: string | null
  email?: string | null
  role?: Role
  locale?: 'fr' | 'en'
  is_active?: boolean
  kind?: 'human' | 'agent' | 'bot'
}

export async function updateUser(db: Queryable, id: number, patch: UserPatch): Promise<UserRow | null> {
  const sets: string[] = []
  const params: unknown[] = [id]
  const allowed: (keyof UserPatch)[] = ['display_name', 'email', 'role', 'locale', 'is_active', 'kind']
  for (const key of allowed) {
    if (patch[key] === undefined) continue
    params.push(patch[key])
    sets.push(`${key} = $${params.length}`)
  }
  if (patch.is_active === true) sets.push('failed_logins = 0', 'locked_until = NULL')
  if (!sets.length) return getUser(db, id)
  const { rows } = await db.query<UserRow>(
    `UPDATE users SET ${sets.join(', ')}, updated_at = now() WHERE id = $1 RETURNING ${USER_COLUMNS}`,
    params,
  )
  return rows[0] ?? null
}

export async function setUserPassword(db: Queryable, id: number, password: string, mustChange: boolean): Promise<void> {
  const hash = await hashPassword(password)
  await db.query(
    `UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = now(),
            failed_logins = 0, locked_until = NULL, updated_at = now()
      WHERE id = $1`,
    [id, hash, mustChange],
  )
}

export async function deleteUser(db: Queryable, id: number): Promise<boolean> {
  const { rowCount } = await db.query('DELETE FROM users WHERE id = $1', [id])
  return (rowCount ?? 0) > 0
}

export type AuthOutcome
  = | { ok: true, userId: number, username: string }
    | { ok: false, reason: 'unknown' | 'inactive' | 'locked' | 'bad-password', userId?: number, lockedNow?: boolean }

interface AuthRow {
  id: string
  username: string
  password_hash: string | null
  is_active: boolean
  locked: boolean
}

/** Vérifie un couple identifiant / mot de passe et tient le compteur d'échecs. */
export async function authenticate(
  db: Queryable,
  username: string,
  password: string,
  settings: AuthSettings,
): Promise<AuthOutcome> {
  const { rows } = await db.query<AuthRow>(
    `SELECT id::text, username, password_hash, is_active,
            (locked_until IS NOT NULL AND locked_until > now()) AS locked
       FROM users WHERE username = $1 AND auth_source = 'local'`,
    [username],
  )
  const user = rows[0]
  if (!user || !user.password_hash) {
    await burnPasswordCheck(password)
    return { ok: false, reason: 'unknown' }
  }
  const userId = Number(user.id)
  if (!user.is_active) {
    await burnPasswordCheck(password)
    return { ok: false, reason: 'inactive', userId }
  }
  if (user.locked) {
    await burnPasswordCheck(password)
    return { ok: false, reason: 'locked', userId }
  }
  if (!(await verifyPassword(password, user.password_hash))) {
    const upd = await db.query<{ locked: boolean }>(
      `UPDATE users SET
              failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END,
              locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
        WHERE id = $1
        RETURNING (locked_until IS NOT NULL AND locked_until > now()) AS locked`,
      [userId, settings.lockoutThreshold, settings.lockoutMinutes],
    )
    return { ok: false, reason: 'bad-password', userId, lockedNow: upd.rows[0]?.locked ?? false }
  }
  await db.query(
    'UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1',
    [userId],
  )
  return { ok: true, userId, username: user.username }
}

export async function verifyUserPassword(db: Queryable, id: number, password: string): Promise<boolean> {
  const { rows } = await db.query<{ password_hash: string | null }>('SELECT password_hash FROM users WHERE id = $1', [id])
  const hash = rows[0]?.password_hash
  if (!hash) {
    await burnPasswordCheck(password)
    return false
  }
  return verifyPassword(password, hash)
}
