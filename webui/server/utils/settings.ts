// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Réglages propres à la console (table appliance_settings), avec bornes.

import type { Queryable } from './db'

export interface AuthSettings {
  sessionIdleMinutes: number
  sessionMaxHours: number
  lockoutThreshold: number
  lockoutMinutes: number
}

const DEFAULTS: AuthSettings = {
  sessionIdleMinutes: 60,
  sessionMaxHours: 12,
  lockoutThreshold: 5,
  lockoutMinutes: 15,
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' ? value : Number.NaN
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback
}

let cache: { at: number, value: AuthSettings } | undefined

export async function getAuthSettings(db: Queryable, maxAgeMs = 30_000): Promise<AuthSettings> {
  if (cache && Date.now() - cache.at < maxAgeMs) return cache.value
  const { rows } = await db.query<{ key: string, value: unknown }>(
    `SELECT key, value FROM appliance_settings WHERE key LIKE 'auth.%'`,
  )
  const map = new Map(rows.map(r => [r.key, r.value]))
  const value: AuthSettings = {
    sessionIdleMinutes: clampInt(map.get('auth.session_idle_minutes'), 5, 1440, DEFAULTS.sessionIdleMinutes),
    sessionMaxHours: clampInt(map.get('auth.session_max_hours'), 1, 168, DEFAULTS.sessionMaxHours),
    lockoutThreshold: clampInt(map.get('auth.lockout_threshold'), 3, 100, DEFAULTS.lockoutThreshold),
    lockoutMinutes: clampInt(map.get('auth.lockout_minutes'), 1, 1440, DEFAULTS.lockoutMinutes),
  }
  cache = { at: Date.now(), value }
  return value
}

export function clearSettingsCache(): void {
  cache = undefined
}
