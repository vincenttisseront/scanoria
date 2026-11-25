// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Ingestion des résultats de scanoria-helper (docs/ARCHITECTURE.md § 5.6) :
// lecture de requests/done et requests/failed, mise à jour de helper_requests
// (ligne créée si l'action vient d'un timer, du premier démarrage ou de la
// ligne de commande), update_history, journal d'audit. Une demande sans
// résultat après 1 h passe en « lost ».

import { lstat, readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import type pg from 'pg'
import { withTransaction, type Queryable } from './db'
import { writeAudit } from './audit'
import { REQUEST_FILE_RE, VERSION_RE, resultSchema, type HelperResult } from '#shared/schemas'
import { recordOffline } from '../offline/ingest'

const MAX_RESULT_BYTES = 1024 * 1024
const INVALID_FILE_RE = /^invalid-[A-Za-z0-9._-]{1,120}\.json$/
const FINAL_STATUSES = new Set(['ok', 'error', 'rejected'])

export interface IngestStats {
  ingested: number
  skipped: number
  invalid: number
  lost: number
}

/** Mémoire des fichiers déjà traités (évite de relire 30 jours de résultats). */
export class IngestMemory {
  readonly seen = new Set<string>()
  primed = false
}

async function readResultFile(path: string): Promise<unknown | undefined> {
  const st = await lstat(path)
  if (!st.isFile() || st.size > MAX_RESULT_BYTES) return undefined
  return JSON.parse(await readFile(path, 'utf8'))
}

function versionOrNull(v: unknown): string | null {
  return typeof v === 'string' && VERSION_RE.test(v) ? v : null
}

async function recordUpdateHistory(
  client: pg.PoolClient,
  result: HelperResult,
  row: { requested_by: string | null, params: Record<string, unknown>, created_at: Date },
): Promise<void> {
  if (result.type !== 'apply-update' && result.type !== 'rollback-update') return
  if (result.status === 'rejected') return
  const out = result.output
  const params = row.params
  let from = versionOrNull(out.from_version)
  let to = versionOrNull(out.to_version) ?? versionOrNull(out.version)
  if (result.type === 'rollback-update') {
    from ??= versionOrNull(params.expected_current)
    to ??= versionOrNull(params.expected_target)
  }
  else {
    from ??= versionOrNull(params.installed_version_hint)
    to ??= versionOrNull(params.version)
  }
  if (!from || !to) return
  let action: 'apply' | 'rollback' | 'auto-rollback' = result.type === 'apply-update' ? 'apply' : 'rollback'
  let status: 'success' | 'failed' | 'rolled-back' = result.status === 'ok' ? 'success' : 'failed'
  if (result.code === 'E_HEALTH_ROLLED_BACK') {
    action = 'auto-rollback'
    status = 'rolled-back'
  }
  const channel = out.channel === 'stable' || out.channel === 'prerelease' ? out.channel : null
  const source = result.type === 'apply-update' && (params.source === 'github' || params.source === 'upload')
    ? params.source
    : null
  await client.query(
    `INSERT INTO update_history (action, from_version, to_version, channel, source, status, code,
                                 request_id, initiated_by, started_at, finished_at, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      action, from, to, channel, source, status, result.code,
      result.id, row.requested_by, result.started_at ?? result.received_at ?? row.created_at,
      result.finished_at, JSON.stringify({ origin: result.origin, message: result.message }),
    ],
  )
}

interface RequestLite {
  status: string
  requested_by: string | null
  params: Record<string, unknown>
  created_at: Date
}

async function ingestOne(pool: pg.Pool, fileName: string, result: HelperResult): Promise<'ingested' | 'skipped'> {
  return withTransaction(pool, async (client) => {
    if (!result.id || !result.type) {
      // Demande illisible (ex. E_INVALID_NAME) : seulement l'audit, une fois.
      const dup = await client.query(
        `SELECT 1 FROM audit_log WHERE action = 'system.helper.rejected-file' AND target_id = $1 LIMIT 1`,
        [fileName],
      )
      if (dup.rowCount) return 'skipped'
      await writeAudit(client, {
        actor: { type: 'system' },
        action: 'system.helper.rejected-file',
        outcome: 'failure',
        targetType: 'helper-request',
        targetId: fileName,
        details: { code: result.code, message: result.message, origin: result.origin },
      })
      return 'ingested'
    }
    const existing = await client.query<RequestLite>(
      'SELECT status, requested_by::text, params, created_at FROM helper_requests WHERE id = $1 FOR UPDATE',
      [result.id],
    )
    let row = existing.rows[0]
    if (row && FINAL_STATUSES.has(row.status)) return 'skipped'
    if (!row) {
      const inserted = await client.query<RequestLite>(
        `INSERT INTO helper_requests (id, type, origin, file_name, params, status, created_at)
         VALUES ($1, $2, $3, $4, '{}'::jsonb, 'pending', $5)
         ON CONFLICT (file_name) DO NOTHING
         RETURNING status, requested_by::text, params, created_at`,
        [result.id, result.type, result.origin, fileName, result.received_at],
      )
      row = inserted.rows[0]
      if (!row) return 'skipped'
    }
    await client.query(
      `UPDATE helper_requests SET status = $2, code = $3, message = $4, output = $5, finished_at = $6
        WHERE id = $1`,
      [result.id, result.status, result.code, result.message.slice(0, 2000), JSON.stringify(result.output), result.finished_at],
    )
    let actor: { type: 'user' | 'system', userId?: number, username?: string } = { type: 'system' }
    if (row.requested_by) {
      const u = await client.query<{ username: string }>('SELECT username FROM users WHERE id = $1', [row.requested_by])
      actor = { type: 'user', userId: Number(row.requested_by), username: u.rows[0]?.username }
    }
    await writeAudit(client, {
      actor,
      action: `system.${result.type}.result`,
      outcome: result.status === 'ok' ? 'success' : 'failure',
      targetType: 'helper-request',
      targetId: result.id,
      requestId: result.id,
      details: { origin: result.origin, status: result.status, code: result.code, message: result.message },
    })
    await recordUpdateHistory(client, result, row)
    await recordOffline(client, result, row)
    return 'ingested'
  })
}

/** Passe en « running » la demande que le helper publie comme en cours. */
export async function markRunning(db: Queryable, currentId: string | null | undefined): Promise<void> {
  if (!currentId) return
  await db.query(`UPDATE helper_requests SET status = 'running' WHERE id = $1 AND status = 'pending'`, [currentId])
}

export async function markLostRequests(db: Queryable): Promise<number> {
  const { rowCount } = await db.query(
    `UPDATE helper_requests SET status = 'lost', finished_at = now()
      WHERE status IN ('pending', 'running') AND created_at < now() - interval '1 hour'`,
  )
  return rowCount ?? 0
}

export async function ingestResults(pool: pg.Pool, requestsDir: string, memory: IngestMemory): Promise<IngestStats> {
  const stats: IngestStats = { ingested: 0, skipped: 0, invalid: 0, lost: 0 }
  if (!memory.primed) {
    const { rows } = await pool.query<{ file_name: string }>(
      `SELECT file_name FROM helper_requests WHERE status IN ('ok', 'error', 'rejected')`,
    )
    for (const r of rows) memory.seen.add(r.file_name)
    memory.primed = true
  }
  for (const dir of ['done', 'failed']) {
    let names: string[]
    try {
      names = (await readdir(join(requestsDir, dir))).sort()
    }
    catch {
      continue
    }
    for (const name of names) {
      if (memory.seen.has(name)) continue
      if (!REQUEST_FILE_RE.test(name) && !INVALID_FILE_RE.test(name)) continue
      let raw: unknown
      try {
        raw = await readResultFile(join(requestsDir, dir, name))
      }
      catch {
        // fichier en cours de remplacement ou JSON invalide : on réessaiera
        continue
      }
      const parsed = resultSchema.safeParse(raw)
      if (!parsed.success) {
        stats.invalid += 1
        memory.seen.add(name)
        console.warn(`[ingest] invalid result file ${dir}/${name}`)
        continue
      }
      if (REQUEST_FILE_RE.test(name) && parsed.data.id && !name.endsWith(`-${parsed.data.id}.json`)) {
        stats.invalid += 1
        memory.seen.add(name)
        console.warn(`[ingest] result id does not match file name ${dir}/${name}`)
        continue
      }
      const outcome = await ingestOne(pool, name, parsed.data)
      stats[outcome] += 1
      memory.seen.add(name)
    }
  }
  stats.lost = await markLostRequests(pool)
  return stats
}
