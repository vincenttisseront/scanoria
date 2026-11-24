// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Lecture et actions de l'API /api/scans : liste filtrable, détail (plan,
// modules, couverture, verdict brut), mise en file manuelle, annulation,
// relance et rejeu à l'identique (G11). Les codes d'erreur propres aux
// analyses sont traduits dans l'espace scans.errors de la console.

import { createError, setResponseStatus, type H3Event } from 'h3'
import { z } from 'zod'
import { SCAN_STATUSES, SCAN_TRIGGERS, SLUG_RE, VERDICTS } from '#shared/analysis'
import { UUID_V4_RE } from '#shared/schemas'
import { writeAudit } from '../utils/audit'
import { getPool, type Queryable } from '../utils/db'
import { clientAddress, requireRole, type AuthContext } from '../utils/http'
import { EnqueueScanError, enqueueScan, type EnqueueErrorCode, type EnqueueScanInput } from './enqueue'
import { EFFECTIVE_PRIORITY_SQL } from './priority'

export type ScanApiErrorCode = 'E_SCAN_NOT_FOUND' | 'E_SCAN_STATE' | 'E_SCAN_LOG' | EnqueueErrorCode

export function scanError(statusCode: number, code: ScanApiErrorCode) {
  return createError({ statusCode, statusMessage: code, data: { code } })
}

export function scanIdParam(raw: string | undefined): string {
  if (!raw || !UUID_V4_RE.test(raw)) throw scanError(404, 'E_SCAN_NOT_FOUND')
  return raw
}

export const scanListQuery = z.object({
  project: z.string().regex(UUID_V4_RE).optional(),
  status: z.enum([...SCAN_STATUSES, 'active']).optional(),
  verdict: z.enum(VERDICTS).optional(),
  trigger: z.enum(SCAN_TRIGGERS).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
}).strict()
export type ScanListQuery = z.infer<typeof scanListQuery>

const LIST_COLUMNS = `s.id, s.project_id, p.name AS project_name, p.slug AS project_slug, s.number, s.trigger, s.priority,
  ${EFFECTIVE_PRIORITY_SQL} AS effective_priority, s.ref, s.commit_sha, pr.slug AS profile, s.status, s.verdict,
  s.attempt, s.error, s.replay_of, s.queued_at, s.started_at, s.finished_at,
  s.external_source`

export async function listScans(db: Queryable, q: ScanListQuery) {
  const where: string[] = []
  const args: unknown[] = []
  const add = (sql: string, v: unknown) => {
    args.push(v)
    where.push(sql.replace('?', `$${args.length}`))
  }
  if (q.project) add('s.project_id = ?', q.project)
  if (q.status === 'active') where.push(`s.status IN ('queued', 'dispatched', 'running', 'ingesting')`)
  else if (q.status) add('s.status = ?', q.status)
  if (q.verdict) add('s.verdict = ?', q.verdict)
  if (q.trigger) add('s.trigger = ?', q.trigger)
  const cond = where.length ? `WHERE ${where.join(' AND ')}` : ''
  // File active : dans l'ordre où le worker la prendra (G17) ; historique : le plus récent d'abord.
  const order = q.status === 'active' || q.status === 'queued'
    ? `CASE WHEN s.status = 'queued' THEN 1 ELSE 0 END, effective_priority DESC, s.queued_at ASC`
    : 's.queued_at DESC'
  const total = await db.query<{ n: number }>(`SELECT count(*)::int AS n FROM scans s ${cond}`, args)
  const items = await db.query(
    `SELECT ${LIST_COLUMNS} FROM scans s JOIN projects p ON p.id = s.project_id JOIN profiles pr ON pr.id = s.profile_id
      ${cond} ORDER BY ${order} LIMIT ${q.limit} OFFSET ${q.offset}`, args)
  return { items: items.rows, total: total.rows[0]?.n ?? 0 }
}

export async function getScan(db: Queryable, id: string) {
  const r = await db.query(
    `SELECT ${LIST_COLUMNS}, g.slug AS gate, s.plan, s.coverage, s.verdict_details, s.upload_id,
            u.username AS requested_by_username, s.api_token_id IS NOT NULL AS by_api_token
       FROM scans s JOIN projects p ON p.id = s.project_id JOIN profiles pr ON pr.id = s.profile_id
       JOIN gates g ON g.id = s.gate_id LEFT JOIN users u ON u.id = s.requested_by
      WHERE s.id = $1`, [id])
  const scan = r.rows[0]
  if (!scan) return null
  const modules = await db.query(
    `SELECT module_id, module_version, image_digest, feeds, status, error_class, attempts, results_count,
            duration_ms, log_path IS NOT NULL AS has_log, started_at, finished_at
       FROM scan_modules WHERE scan_id = $1 ORDER BY module_id`, [id])
  let position: number | null = null
  if (scan.status === 'queued') {
    const q = await db.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM scans s WHERE s.status = 'queued' AND s.id <> $1
          AND (${EFFECTIVE_PRIORITY_SQL} > $2::int
               OR (${EFFECTIVE_PRIORITY_SQL} = $2::int AND s.queued_at < $3::timestamptz))`,
      [id, scan.effective_priority, scan.queued_at])
    position = (q.rows[0]?.n ?? 0) + 1
  }
  return { ...scan, queue_position: position, modules: modules.rows }
}

/** Journal d'un module copié par le worker (G20) : chemin relatif sous scan-logs/. */
export async function moduleLogPath(db: Queryable, scanId: string, moduleId: string): Promise<string | null> {
  const r = await db.query<{ log_path: string | null }>('SELECT log_path FROM scan_modules WHERE scan_id = $1 AND module_id = $2', [scanId, moduleId])
  const p = r.rows[0]?.log_path
  return p && /^[0-9a-f-]{36}\/[a-z0-9][a-z0-9-]{1,40}\.log$/.test(p) ? p : null
}

export const scanCreateBody = z.object({
  project_id: z.string().regex(UUID_V4_RE),
  ref: z.string().min(1).max(255).optional(),
  profile: z.string().regex(SLUG_RE).optional(),
}).strict()

function actorOf(event: H3Event, auth: AuthContext) {
  return { type: 'user' as const, userId: auth.user.id, username: auth.user.username, ip: clientAddress(event) }
}

/** Met une analyse en file pour l'utilisateur connecté (operator), avec audit. */
export async function enqueueFromApi(event: H3Event, input: Omit<EnqueueScanInput, 'requestedBy'>, action: string, targetId?: string) {
  const auth = requireRole(event, 'operator')
  const pool = getPool()
  let res
  try {
    res = await enqueueScan(pool, { ...input, requestedBy: auth.user.id })
  }
  catch (err) {
    if (err instanceof EnqueueScanError) {
      await writeAudit(pool, {
        actor: actorOf(event, auth), action, outcome: 'failure', targetType: 'scan', targetId: targetId ?? null, details: { error: err.code },
      }).catch(() => {})
      throw scanError(err.code === 'E_SCAN_PROJECT_NOT_FOUND' ? 404 : 409, err.code)
    }
    throw err
  }
  await writeAudit(pool, {
    actor: actorOf(event, auth), action, outcome: 'success', targetType: 'scan', targetId: res.scanId,
    details: {
      project_id: input.projectId, ref: input.ref, trigger: input.trigger, profile: input.profileSlug ?? null,
      replay_of: input.replayOf ?? null, merged: res.merged,
    },
  })
  setResponseStatus(event, res.merged ? 200 : 202)
  return { scan_id: res.scanId, number: res.number, merged: res.merged }
}

export async function auditScanAction(event: H3Event, auth: AuthContext, action: string, scanId: string, outcome: 'success' | 'failure', details: Record<string, unknown> = {}) {
  await writeAudit(getPool(), { actor: actorOf(event, auth), action, outcome, targetType: 'scan', targetId: scanId, details })
}
