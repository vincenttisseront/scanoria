// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// § 7.2, mode tiré (release_mode = 'pull', défaut) : l'appliance interroge la
// forge de chaque projet (toutes les 10 minutes, recul exponentiel jusqu'à
// 6 h en cas d'erreur), lit les tags qui correspondent à release_patterns et
// ceux des pré-versions, et analyse chaque nouveau tag avec le profil release
// (trigger 'release', priorité maximale, G17). Requêtes sortantes seulement.
// - Un tag déjà vu n'est jamais réanalysé (release_candidates).
// - Un tag déplacé (même nom, autre commit) est signalé une fois dans l'audit,
//   sans réanalyse silencieuse.
// - Premier passage d'un projet : seul le tag le plus récent est analysé, les
//   anciens sont notés comme vus (aucune avalanche d'analyses).

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { enqueueScan } from '../scans/enqueue'
import { forgeAccess } from '../forges/index'
import { projectForge } from '../forges/context'
import { isSafeTag, releaseForge, type ForgeTag } from '../forges/release'
import { compareTags } from './compare'
import { publishReleaseGate } from './gate'

type Db = Queryable & Pick<pg.Pool, 'connect'>

export const RELEASE_POLL_MS = 10 * 60_000
const MAX_BACKOFF_MS = 6 * 3600_000
const PROJECTS_PER_PASS = 20
const NEW_TAGS_PER_PROJECT = 5

const state = new Map<string, { next: number, failures: number }>()

/** Tests : oublie le planning d'interrogation. */
export function resetReleasePolling(): void {
  state.clear()
}

/** Motif de tag (glob) : « * » toute suite de caractères, « ? » un caractère. */
export function tagMatches(tag: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    const re = new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`)
    return re.test(tag)
  })
}

/** Tags retenus : motifs du projet ou pré-version déclarée dans la forge. */
export function releaseTags(tags: ForgeTag[], patterns: string[]): ForgeTag[] {
  return tags.filter(t => isSafeTag(t.name) && (tagMatches(t.name, patterns) || t.prerelease))
}

export interface ReleasePollResult { projects: number, scans: number, moved: number, errors: number }

/**
 * Analyse de release d'un tag nouveau, ou d'un tag noté comme vu sans analyse
 * (premier passage) quand la CI la demande ; null si le tag a déjà son analyse.
 */
export async function enqueueRelease(db: Db, projectId: string, tag: string, commit: string, source: 'pull' | 'push', opts: { requestedBy?: number, apiTokenId?: string } = {}): Promise<{ scanId: string, number: number, existing: boolean } | null> {
  // Verrou consultatif par (projet, tag), tenu jusqu'au rattachement de
  // l'analyse : deux appels simultanés (relance de CI, interrogation et CI en
  // même temps) n'analysent jamais deux fois la même release.
  const lock = await db.connect()
  const key = `scanoria-release:${projectId}:${tag}`
  try {
    await lock.query('SELECT pg_advisory_lock(hashtext($1))', [key])
    const cur = (await lock.query<{ commit_sha: string, scan_id: string | null, number: number | null }>(
      `SELECT rc.commit_sha, rc.scan_id::text, s.number FROM release_candidates rc LEFT JOIN scans s ON s.id = rc.scan_id
        WHERE rc.project_id = $1 AND rc.tag = $2`, [projectId, tag])).rows[0]
    if (cur && cur.commit_sha !== commit) return null
    if (cur?.scan_id) return { scanId: cur.scan_id, number: cur.number ?? 0, existing: true }
    await lock.query(
      `INSERT INTO release_candidates (project_id, tag, commit_sha, source) VALUES ($1, $2, $3, $4)
       ON CONFLICT (project_id, tag) DO UPDATE SET source = EXCLUDED.source, seen_at = now()
         WHERE release_candidates.scan_id IS NULL AND release_candidates.commit_sha = EXCLUDED.commit_sha`, [projectId, tag, commit, source])
    const res = await enqueueScan(db, { projectId, ref: tag, commit, trigger: 'release', ...opts })
    await lock.query('UPDATE release_candidates SET scan_id = $3 WHERE project_id = $1 AND tag = $2 AND scan_id IS NULL', [projectId, tag, res.scanId])
    await writeAudit(db, { actor: { type: 'system' }, action: 'release.detected', outcome: 'success', targetType: 'scan', targetId: res.scanId, details: { tag, commit, source } })
    void publishReleaseGate(db, res.scanId).catch(() => {})
    return { scanId: res.scanId, number: res.number, existing: false }
  }
  finally {
    await lock.query('SELECT pg_advisory_unlock(hashtext($1))', [key]).catch(() => {})
    lock.release()
  }
}

/** Tag déplacé : signalé une fois par (tag, nouveau commit), jamais réanalysé en silence. */
export async function reportMovedTag(db: Queryable, projectId: string, tag: string, known: string, seen: string): Promise<boolean> {
  const dup = await db.query(
    `SELECT 1 FROM audit_log WHERE action = 'release.tag.moved' AND target_type = 'project' AND target_id = $1
        AND details ->> 'tag' = $2 AND details ->> 'commit' = $3 LIMIT 1`, [projectId, tag, seen])
  if (dup.rowCount) return false
  await writeAudit(db, { actor: { type: 'system' }, action: 'release.tag.moved', outcome: 'failure', targetType: 'project', targetId: projectId, details: { tag, known_commit: known, commit: seen } })
  return true
}

async function pollProject(db: Db, projectId: string, patterns: string[], out: ReleasePollResult): Promise<void> {
  const ctx = await projectForge(db, projectId)
  if (!ctx) return
  const tags = releaseTags(await releaseForge(await forgeAccess(db, ctx.forge)).tags(ctx.repo), patterns)
  const known = new Map((await db.query<{ tag: string, commit_sha: string }>(
    'SELECT tag, commit_sha FROM release_candidates WHERE project_id = $1', [projectId])).rows.map(r => [r.tag, r.commit_sha]))
  const fresh: ForgeTag[] = []
  for (const t of tags) {
    const k = known.get(t.name)
    if (k === undefined) fresh.push(t)
    else if (k !== t.commit_sha && await reportMovedTag(db, projectId, t.name, k, t.commit_sha)) out.moved++
  }
  if (!fresh.length) return
  fresh.sort((a, b) => compareTags(b.name, a.name))
  // Premier passage : le tag le plus récent seulement ; les autres sont notés comme vus.
  const scan = known.size === 0 ? fresh.slice(0, 1) : fresh.slice(0, NEW_TAGS_PER_PROJECT)
  if (known.size === 0) {
    for (const t of fresh.slice(1)) {
      await db.query(`INSERT INTO release_candidates (project_id, tag, commit_sha, source) VALUES ($1, $2, $3, 'pull') ON CONFLICT DO NOTHING`, [projectId, t.name, t.commit_sha])
    }
  }
  for (const t of scan.reverse()) {
    if ((await enqueueRelease(db, projectId, t.name, t.commit_sha, 'pull'))?.existing === false) out.scans++
  }
}

/** Une passe du mode tiré ; ne lève jamais (une forge en erreur n'arrête pas les autres). */
export async function pollReleases(db: Db, now = new Date()): Promise<ReleasePollResult> {
  const out: ReleasePollResult = { projects: 0, scans: 0, moved: 0, errors: 0 }
  const { rows } = await db.query<{ id: string, release_patterns: string[] }>(
    `SELECT p.id::text, p.release_patterns FROM projects p JOIN forges f ON f.id = p.forge_id
      WHERE p.release_mode = 'pull' AND p.archived_at IS NULL AND p.suspended_at IS NULL AND p.repo_full_name IS NOT NULL
        AND (p.credential_id IS NOT NULL OR f.credential_id IS NOT NULL OR EXISTS (SELECT 1 FROM forge_apps a WHERE a.forge_id = f.id))
      ORDER BY p.created_at LIMIT 1000`)
  for (const p of rows) {
    if (out.projects >= PROJECTS_PER_PASS) break
    const s = state.get(p.id) ?? { next: 0, failures: 0 }
    if (s.next > now.getTime()) continue
    out.projects++
    try {
      await pollProject(db, p.id, p.release_patterns, out)
      state.set(p.id, { next: now.getTime() + RELEASE_POLL_MS, failures: 0 })
    }
    catch (err) {
      out.errors++
      const failures = s.failures + 1
      state.set(p.id, { next: now.getTime() + Math.min(MAX_BACKOFF_MS, RELEASE_POLL_MS * 2 ** failures), failures })
      console.error(`[release] poll ${p.id}: ${(err as { code?: string })?.code ?? 'error'}`)
    }
  }
  return out
}
