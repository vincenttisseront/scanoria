// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Mode tiré (J1, section 7.2) : quand la forge ne joint pas l'appliance
// (aucun webhook reçu depuis PUSH_WINDOW), l'appliance l'interroge. Requêtes
// sortantes seulement :
// - PR ouvertes de chaque projet actif → analyse de PR (G18) si leur commit
//   de tête est nouveau ;
// - commentaires récents de ces PR → /scanoria accept (J15), chacun traité une
//   fois (même marque que le webhook) ;
// - G18 : analyse complète nocturne de la branche principale d'un projet qui a
//   eu des analyses de PR incrémentales.
// Bornes : projets, PR et commentaires limités par passe ; une forge en
// erreur n'arrête pas les autres.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { enqueueScan } from '../scans/enqueue'
import { projectForge } from './context'
import { forgeMode } from './status'
import { enqueuePullRequestScan, handlePrComment } from './pr'

type Db = Queryable & Pick<pg.Pool, 'connect'>

export const POLL_INTERVAL_MS = 5 * 60_000
const PROJECTS_PER_PASS = 50
const PRS_PER_PROJECT = 20
const COMMENT_LOOKBACK_MS = 24 * 3600_000

const lastPoll = new Map<string, number>()

/** Oublie les dates d'interrogation (tests). */
export function resetPullRequestPolling(): void {
  lastPoll.clear()
}

export interface PollResult { projects: number, scans: number, comments: number, errors: number }

export async function pollPullRequests(db: Db, now = new Date()): Promise<PollResult> {
  const out: PollResult = { projects: 0, scans: 0, comments: 0, errors: 0 }
  const { rows } = await db.query<{ id: string, forge_id: string }>(
    `SELECT p.id::text, p.forge_id::text FROM projects p JOIN forges f ON f.id = p.forge_id
      WHERE p.archived_at IS NULL AND p.suspended_at IS NULL AND p.repo_full_name IS NOT NULL
        AND p.schedule <> 'none' AND (p.credential_id IS NOT NULL OR f.credential_id IS NOT NULL)
      ORDER BY p.created_at LIMIT 500`)
  const modes = new Map<string, Awaited<ReturnType<typeof forgeMode>>>()
  for (const p of rows) {
    if (out.projects >= PROJECTS_PER_PASS) break
    if ((lastPoll.get(p.id) ?? 0) > now.getTime() - POLL_INTERVAL_MS) continue
    if (!modes.has(p.forge_id)) modes.set(p.forge_id, await forgeMode(db, p.forge_id))
    if (modes.get(p.forge_id) === 'push') continue
    lastPoll.set(p.id, now.getTime())
    out.projects++
    try {
      const ctx = await projectForge(db, p.id)
      if (!ctx) continue
      const since = new Date(now.getTime() - COMMENT_LOOKBACK_MS).toISOString()
      for (const pr of await ctx.publisher.openPullRequests(ctx.repo, PRS_PER_PROJECT)) {
        if (await enqueuePullRequestScan(db, ctx, pr)) out.scans++
        for (const c of await ctx.publisher.comments(ctx.repo, pr.number, since)) {
          const r = await handlePrComment(db, ctx, { number: pr.number, comment: c })
          if (r !== 'ignored') out.comments++
        }
      }
    }
    catch {
      out.errors++
    }
  }
  return out
}

/**
 * G18 : analyse complète nocturne de la branche principale des projets qui
 * ont eu une analyse de PR incrémentale depuis la dernière analyse complète
 * de cette branche (au plus une par jour). Mode poussé ou tiré.
 */
export async function nightlyFullScans(db: Db, now = new Date()): Promise<number> {
  const hour = now.getUTCHours()
  if (hour < 1 || hour > 4) return 0
  const { rows } = await db.query<{ id: string, default_branch: string }>(
    `SELECT p.id::text, p.default_branch FROM projects p
      WHERE p.archived_at IS NULL AND p.suspended_at IS NULL AND p.default_branch IS NOT NULL
        AND EXISTS (SELECT 1 FROM scans s WHERE s.project_id = p.id AND s.incremental AND s.queued_at > $1::timestamptz - interval '1 day')
        AND NOT EXISTS (SELECT 1 FROM scans s WHERE s.project_id = p.id AND NOT s.incremental AND s.pull_request IS NULL
                          AND s.ref = p.default_branch AND s.queued_at > $1::timestamptz - interval '20 hours')
      LIMIT 100`, [now.toISOString()])
  for (const p of rows) await enqueueScan(db, { projectId: p.id, ref: p.default_branch, trigger: 'schedule' })
  return rows.length
}
