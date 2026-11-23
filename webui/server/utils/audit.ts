// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Journal d'audit : ajout seul (UPDATE interdit par déclencheur en base).
// Les détails ne contiennent jamais de secret : les clés suspectes sont retirées.

import type { Queryable } from './db'

export type AuditOutcome = 'success' | 'failure' | 'denied'

export interface AuditActor {
  type: 'user' | 'system' | 'anonymous'
  userId?: number | null
  username?: string | null
  ip?: string | null
}

export interface AuditEntry {
  actor: AuditActor
  action: string
  outcome: AuditOutcome
  targetType?: string | null
  targetId?: string | null
  requestId?: string | null
  details?: Record<string, unknown>
}

const SECRET_KEY_RE = /pass(word)?|secret|token|private|key_pem|privkey|cookie|authorization/i
const ACTION_RE = /^[a-z][a-z0-9-]*(\.[a-z0-9-]+)+$/

/** Retire récursivement les champs qui pourraient porter un secret. */
export function redactSecrets(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[truncated]'
  if (Array.isArray(value)) return value.slice(0, 100).map(v => redactSecrets(v, depth + 1))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY_RE.test(k)) continue
      out[k] = redactSecrets(v, depth + 1)
    }
    return out
  }
  if (typeof value === 'string' && value.length > 4000) return `${value.slice(0, 4000)}…`
  return value
}

export async function writeAudit(db: Queryable, entry: AuditEntry): Promise<void> {
  if (!ACTION_RE.test(entry.action)) throw new Error(`invalid audit action: ${entry.action}`)
  const details = redactSecrets(entry.details ?? {}) as Record<string, unknown>
  await db.query(
    `INSERT INTO audit_log (actor_user_id, actor_username, actor_type, actor_ip, action,
                            target_type, target_id, outcome, request_id, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      entry.actor.userId ?? null,
      entry.actor.username ?? (entry.actor.type === 'system' ? 'system' : null),
      entry.actor.type,
      entry.actor.ip ?? null,
      entry.action,
      entry.targetType ?? null,
      entry.targetId ? String(entry.targetId).slice(0, 128) : null,
      entry.outcome,
      entry.requestId ?? null,
      JSON.stringify(details),
    ],
  )
}

export interface AuditRow {
  id: string
  occurred_at: string
  actor_user_id: string | null
  actor_username: string | null
  actor_type: string
  actor_ip: string | null
  action: string
  target_type: string | null
  target_id: string | null
  outcome: AuditOutcome
  request_id: string | null
  details: Record<string, unknown>
}

export interface AuditFilter {
  limit: number
  offset: number
  action?: string
  outcome?: AuditOutcome
  actor?: string
}

export async function listAudit(db: Queryable, f: AuditFilter): Promise<{ items: AuditRow[], total: number }> {
  const where: string[] = []
  const params: unknown[] = []
  if (f.action) {
    params.push(`${f.action.replace(/[\\%_]/g, m => `\\${m}`)}%`)
    where.push(`action LIKE $${params.length}`)
  }
  if (f.outcome) {
    params.push(f.outcome)
    where.push(`outcome = $${params.length}`)
  }
  if (f.actor) {
    params.push(f.actor)
    where.push(`actor_username = $${params.length}`)
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const total = await db.query<{ n: string }>(`SELECT count(*) AS n FROM audit_log ${clause}`, params)
  params.push(f.limit, f.offset)
  const rows = await db.query<AuditRow>(
    `SELECT id::text, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS occurred_at,
            actor_user_id::text, actor_username, actor_type, host(actor_ip) AS actor_ip, action,
            target_type, target_id, outcome, request_id::text, details
       FROM audit_log ${clause}
      ORDER BY occurred_at DESC, id DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  )
  return { items: rows.rows, total: Number(total.rows[0]?.n ?? 0) }
}

export async function getAudit(db: Queryable, id: string): Promise<AuditRow | null> {
  const rows = await db.query<AuditRow>(
    `SELECT id::text, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS occurred_at,
            actor_user_id::text, actor_username, actor_type, host(actor_ip) AS actor_ip, action,
            target_type, target_id, outcome, request_id::text, details
       FROM audit_log WHERE id = $1`,
    [id],
  )
  return rows.rows[0] ?? null
}
