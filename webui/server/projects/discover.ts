// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Découverte des dépôts d'une forge (principe 8) : chaque dépôt accessible au
// jeton devient un projet actif, avec le profil « complet », le gate
// « defaut » et la planification « on-commit ». Un dépôt vide ou archivé sur
// la forge est ignoré (il sera repris quand il aura du contenu). Un projet
// archivé dans la console n'est jamais recréé : la paire (forge, dépôt) existe.

import type { Queryable } from '../utils/db'
import { writeAudit } from '../utils/audit'
import { ForgeError } from '../forges/http'
import { getForge, openForge, type ForgeRepo, type ForgeRow } from '../forges'
import { ProjectExistsError, createProject } from './service'

export interface DiscoveryResult {
  repos: number
  created: string[]
  skipped: number
  error: string | null
}

function usable(r: ForgeRepo): boolean {
  return !r.archived && !r.empty && !!r.default_branch
}

export async function discoverForge(db: Queryable, forge: ForgeRow, actor: { userId?: number | null, username?: string | null } = {}): Promise<DiscoveryResult> {
  const result: DiscoveryResult = { repos: 0, created: [], skipped: 0, error: null }
  try {
    const client = await openForge(db, forge)
    const repos = await client.listRepos()
    result.repos = repos.length
    const { rows } = await db.query<{ repo_full_name: string }>(
      `SELECT repo_full_name FROM projects WHERE forge_id = $1 AND repo_full_name IS NOT NULL`, [forge.id])
    const known = new Set(rows.map(r => r.repo_full_name.toLowerCase()))
    for (const repo of repos) {
      if (known.has(repo.full_name.toLowerCase()) || !usable(repo)) {
        result.skipped++
        continue
      }
      try {
        const p = await createProject(db, {
          name: repo.full_name,
          sourceKind: 'git',
          forgeId: forge.id,
          repoFullName: repo.full_name,
          repoUrl: repo.clone_url,
          credentialId: forge.credential_id,
          defaultBranch: repo.default_branch,
          schedule: 'on-commit',
        })
        result.created.push(p.id)
        known.add(repo.full_name.toLowerCase())
      }
      catch (err) {
        if (!(err instanceof ProjectExistsError)) throw err
        result.skipped++
      }
    }
    await db.query(`UPDATE forges SET last_discovery_at = now(), last_error = NULL WHERE id = $1`, [forge.id])
  }
  catch (err) {
    result.error = err instanceof ForgeError ? err.code : 'E_DISCOVERY'
    await db.query(`UPDATE forges SET last_discovery_at = now(), last_error = $2 WHERE id = $1`, [forge.id, result.error])
  }
  await writeAudit(db, {
    actor: actor.userId ? { type: 'user', userId: actor.userId, username: actor.username } : { type: 'system' },
    action: 'forge.discover',
    outcome: result.error ? 'failure' : 'success',
    targetType: 'forge',
    targetId: forge.id,
    details: { forge: forge.name, repos: result.repos, created: result.created.length, skipped: result.skipped, error: result.error },
  })
  return result
}

export const DISCOVERY_INTERVAL_MS = 60 * 60 * 1000

/** Forges dont la découverte est due (activée, avec jeton, plus d'une heure). */
export async function dueForges(db: Queryable, now: Date): Promise<ForgeRow[]> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT id::text FROM forges
      WHERE discovery AND credential_id IS NOT NULL AND kind <> 'gitlab'
        AND (last_discovery_at IS NULL OR last_discovery_at <= $1::timestamptz - interval '1 hour')
      ORDER BY last_discovery_at NULLS FIRST LIMIT 20`,
    [now.toISOString()],
  )
  const out: ForgeRow[] = []
  for (const r of rows) {
    const f = await getForge(db, r.id)
    if (f) out.push(f)
  }
  return out
}
