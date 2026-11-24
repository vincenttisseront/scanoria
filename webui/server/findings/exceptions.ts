// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Exceptions motivées et datées par projet (§ 6.1). Une exception échue ou
// révoquée cesse de s'appliquer d'elle-même (le quality gate, chantier E, ne
// lit que revoked_at IS NULL AND expires_on >= current_date). Aucun avis ni
// résultat malveillant ne peut être exempté (H4).

import { z } from 'zod'
import { EXCEPTION_KINDS, ExceptionTargets } from '#shared/analysis'
import type { Queryable } from '../utils/db'

/** Durée maximale d'une exception : elle doit être revue au moins une fois par an. */
export const MAX_EXCEPTION_DAYS = 366

const dateSchema = z.string().regex(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/)

const base = {
  project_id: z.string().uuid(),
  reason: z.string().trim().min(3).max(2000),
  expires_on: dateSchema,
}
export const exceptionCreateSchema = z.discriminatedUnion('kind', [
  z.strictObject({ ...base, kind: z.literal('path'), target: ExceptionTargets.path }),
  z.strictObject({ ...base, kind: z.literal('rule'), target: ExceptionTargets.rule }),
  z.strictObject({ ...base, kind: z.literal('vuln'), target: ExceptionTargets.vuln }),
  z.strictObject({ ...base, kind: z.literal('finding'), target: ExceptionTargets.finding }),
  z.strictObject({ ...base, kind: z.literal('module'), target: ExceptionTargets.module }),
])

export type ExceptionCreate = {
  project_id: string
  kind: (typeof EXCEPTION_KINDS)[number]
  target: Record<string, unknown>
  reason: string
  expires_on: string
}

export class ExceptionError extends Error {
  constructor(public code: 'E_NOT_FOUND' | 'E_MALICIOUS' | 'E_VALIDATION') {
    super(code)
  }
}

/** Date du jour (UTC) décalée de n jours, au format AAAA-MM-JJ. */
export function isoDay(offsetDays = 0, now = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + offsetDays)).toISOString().slice(0, 10)
}

export interface ExceptionRow {
  id: string
  project_id: string
  kind: string
  target: Record<string, unknown>
  reason: string
  expires_on: string
  created_by: string | null
  created_at: string
  revoked_at: string | null
  revoked_by: string | null
  active: boolean
  expired: boolean
}

const COLUMNS = `e.id, e.project_id, e.kind, e.target, e.reason, to_char(e.expires_on, 'YYYY-MM-DD') AS expires_on,
  uc.username AS created_by, to_char(e.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS created_at,
  to_char(e.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at, ur.username AS revoked_by,
  (e.revoked_at IS NULL AND e.expires_on >= current_date) AS active,
  (e.revoked_at IS NULL AND e.expires_on < current_date) AS expired`

export async function listExceptions(db: Queryable, projectId: string, includeInactive: boolean): Promise<ExceptionRow[]> {
  const r = await db.query<ExceptionRow>(
    `SELECT ${COLUMNS} FROM exceptions e
       LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ur ON ur.id = e.revoked_by
      WHERE e.project_id = $1 ${includeInactive ? '' : 'AND e.revoked_at IS NULL AND e.expires_on >= current_date'}
      ORDER BY e.created_at DESC LIMIT 500`,
    [projectId],
  )
  return r.rows
}

export async function createException(db: Queryable, input: ExceptionCreate, userId: number | null, today = isoDay()): Promise<ExceptionRow> {
  const max = isoDay(MAX_EXCEPTION_DAYS, new Date(`${today}T00:00:00Z`))
  if (input.expires_on < today || input.expires_on > max) throw new ExceptionError('E_VALIDATION')
  const project = await db.query('SELECT 1 FROM projects WHERE id = $1', [input.project_id])
  if (!project.rowCount) throw new ExceptionError('E_NOT_FOUND')
  if (input.kind === 'vuln' && /^MAL-/i.test(String(input.target.vuln_id))) throw new ExceptionError('E_MALICIOUS')
  if (input.kind === 'finding') {
    const f = await db.query<{ malicious: boolean }>('SELECT malicious FROM findings WHERE id = $1 AND project_id = $2', [input.target.finding_id, input.project_id])
    if (!f.rows[0]) throw new ExceptionError('E_NOT_FOUND')
    if (f.rows[0].malicious) throw new ExceptionError('E_MALICIOUS')
  }
  const r = await db.query<{ id: string }>(
    `INSERT INTO exceptions (project_id, kind, target, reason, expires_on, created_by)
     VALUES ($1, $2, $3, $4, $5::date, $6) RETURNING id`,
    [input.project_id, input.kind, JSON.stringify(input.target), input.reason, input.expires_on, userId],
  )
  return (await getException(db, r.rows[0]!.id))!
}

export async function getException(db: Queryable, id: string): Promise<ExceptionRow | null> {
  const r = await db.query<ExceptionRow>(
    `SELECT ${COLUMNS} FROM exceptions e
       LEFT JOIN users uc ON uc.id = e.created_by LEFT JOIN users ur ON ur.id = e.revoked_by
      WHERE e.id = $1`,
    [id],
  )
  return r.rows[0] ?? null
}

/** Révocation (l'historique est gardé). Sans effet sur une exception déjà révoquée. */
export async function revokeException(db: Queryable, id: string, userId: number | null): Promise<ExceptionRow> {
  await db.query('UPDATE exceptions SET revoked_at = now(), revoked_by = $2 WHERE id = $1 AND revoked_at IS NULL', [id, userId])
  const row = await getException(db, id)
  if (!row) throw new ExceptionError('E_NOT_FOUND')
  return row
}
