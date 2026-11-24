// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Planification des projets, appelée par scanoria-worker (chantier C) environ
// chaque minute : runProjectSchedules(db, now, enqueueScan). Un cycle :
// 1. découvre les dépôts des forges dont la découverte est due (chaque heure) ;
// 2. détecte le contenu des projets qui n'ont pas encore de détection (F1) ;
// 3. on-commit (défaut) : interroge le dernier commit de chaque branche suivie,
//    au plus toutes les 5 minutes par projet, et demande une analyse si ce
//    commit n'a pas encore été analysé sur cette branche ;
// 4. daily : une analyse par jour et par branche, à une heure étalée de façon
//    déterministe par projet (aussi pour un dépôt sans accès à l'API de sa
//    forge, qui ne peut pas être interrogé à chaque commit).
// Le cycle ne lève jamais : chaque erreur est comptée et le cycle continue.

import { createHash } from 'node:crypto'
import type { Queryable } from '../utils/db'
import type { ScanTrigger } from '#shared/analysis'
import { ForgeError } from '../forges/http'
import { discoverForge, dueForges } from './discover'
import { getProject, projectClient, refreshDetection, type ProjectRow } from './service'

/** Contrat 4 (chantier C) : webui/server/scans/enqueue.ts. */
export type EnqueueScan = (db: Queryable, input: {
  projectId: string
  ref: string
  commit?: string
  trigger: ScanTrigger
  profileSlug?: string
  requestedBy?: number
}) => Promise<{ scanId: string, number: number }>

export interface ScheduleResult {
  discovered: number
  detected: number
  enqueued: number
  errors: number
}

export const POLL_INTERVAL_MS = 5 * 60 * 1000
const DETECTIONS_PER_CYCLE = 10
const POLLS_PER_CYCLE = 50
const DETECTION_RETRY = '1 hour'

/** Minute du jour (UTC) de l'analyse quotidienne d'un projet : étalée et stable. */
export function dailySlotMinute(projectId: string): number {
  return createHash('sha256').update(projectId).digest().readUInt32BE(0) % 1440
}

/** Début du créneau quotidien en cours (le plus récent ≤ now). */
export function currentDailySlot(projectId: string, now: Date): Date {
  const day = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())
  const slot = new Date(day + dailySlotMinute(projectId) * 60_000)
  return slot <= now ? slot : new Date(slot.getTime() - 86_400_000)
}

function branchesOf(p: Pick<ProjectRow, 'tracked_branches' | 'default_branch'>): string[] {
  const list = p.tracked_branches.length ? p.tracked_branches : (p.default_branch ? [p.default_branch] : [])
  return [...new Set(list)].slice(0, 20)
}

async function lastScannedCommit(db: Queryable, projectId: string, ref: string): Promise<string | null> {
  const { rows } = await db.query<{ commit_sha: string | null }>(
    `SELECT commit_sha FROM scans WHERE project_id = $1 AND ref = $2 AND status <> 'cancelled'
      ORDER BY queued_at DESC LIMIT 1`,
    [projectId, ref],
  )
  return rows[0]?.commit_sha ?? null
}

/** Réserve l'interrogation d'un projet (atomique : deux workers ne la font pas deux fois). */
async function claimPoll(db: Queryable, projectId: string, now: Date): Promise<boolean> {
  const res = await db.query(
    `UPDATE projects SET last_polled_at = $2
      WHERE id = $1 AND (last_polled_at IS NULL OR last_polled_at <= $2::timestamptz - interval '5 minutes')`,
    [projectId, now.toISOString()],
  )
  return (res.rowCount ?? 0) > 0
}

async function pollOnCommit(db: Queryable, p: ProjectRow, now: Date, enqueue: EnqueueScan): Promise<{ enqueued: number, polled: boolean }> {
  const access = await projectClient(db, p)
  if (!access) return { enqueued: 0, polled: false }
  if (!(await claimPoll(db, p.id, now))) return { enqueued: 0, polled: true }
  let enqueued = 0
  for (const branch of branchesOf(p)) {
    const commit = await access.client.latestCommit(access.fullName, branch)
    if (branch === p.default_branch && commit !== p.last_commit) {
      await db.query(`UPDATE projects SET last_commit = $2 WHERE id = $1`, [p.id, commit])
    }
    if ((await lastScannedCommit(db, p.id, branch)) === commit) continue
    await enqueue(db, { projectId: p.id, ref: branch, commit, trigger: 'commit' })
    enqueued++
  }
  return { enqueued, polled: true }
}

async function runDaily(db: Queryable, p: ProjectRow, now: Date, enqueue: EnqueueScan): Promise<number> {
  if (!(await claimPoll(db, p.id, now))) return 0
  const slot = currentDailySlot(p.id, now)
  const { rows } = await db.query<{ n: string }>(
    `SELECT count(*) AS n FROM scans WHERE project_id = $1 AND trigger = 'schedule' AND queued_at >= $2`,
    [p.id, slot.toISOString()],
  )
  if (Number(rows[0]?.n ?? 0) > 0) return 0
  const refs = p.source_kind === 'archive' ? (p.upload_id ? ['archive'] : []) : branchesOf(p)
  for (const ref of refs) await enqueue(db, { projectId: p.id, ref, trigger: 'schedule' })
  return refs.length
}

export async function runProjectSchedules(db: Queryable, now: Date, enqueue: EnqueueScan): Promise<ScheduleResult> {
  const result: ScheduleResult = { discovered: 0, detected: 0, enqueued: 0, errors: 0 }

  for (const forge of await dueForges(db, now).catch(() => [])) {
    const r = await discoverForge(db, forge).catch(() => null)
    if (!r || r.error) result.errors++
    else result.discovered += r.created.length
  }

  const { rows: toDetect } = await db.query<{ id: string }>(
    `SELECT id::text FROM projects
      WHERE archived_at IS NULL AND source_kind = 'git'
        AND (detection IS NULL OR (detection ? 'error' AND (detection->>'analyzed_at')::timestamptz <= $1::timestamptz - interval '${DETECTION_RETRY}'))
      ORDER BY created_at LIMIT ${DETECTIONS_PER_CYCLE}`,
    [now.toISOString()],
  )
  for (const { id } of toDetect) {
    const p = await getProject(db, id)
    if (!p) continue
    const updated = await refreshDetection(db, p, now).catch(() => null)
    if (updated?.detection && !('error' in updated.detection)) result.detected++
    else result.errors++
  }

  const { rows: due } = await db.query<{ id: string }>(
    `SELECT id::text FROM projects
      WHERE archived_at IS NULL AND schedule <> 'none'
        AND (last_polled_at IS NULL OR last_polled_at <= $1::timestamptz - interval '5 minutes')
      ORDER BY last_polled_at NULLS FIRST, created_at LIMIT ${POLLS_PER_CYCLE}`,
    [now.toISOString()],
  )
  for (const { id } of due) {
    const p = await getProject(db, id)
    if (!p) continue
    try {
      if (p.schedule === 'on-commit' && p.source_kind === 'git') {
        const r = await pollOnCommit(db, p, now, enqueue)
        if (r.polled) {
          result.enqueued += r.enqueued
          continue
        }
      }
      // daily, ou on-commit sans accès à l'API de la forge (URL libre).
      result.enqueued += await runDaily(db, p, now, enqueue)
    }
    catch (err) {
      result.errors++
      if (!(err instanceof ForgeError)) console.error('[schedule] project', p.id, (err as Error)?.message)
    }
  }
  return result
}
