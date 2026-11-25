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
import { forgeAccess as forgeAccessFor, getForge, openForge, type ForgeRepo, type ForgeRow } from '../forges'
import { cloneUrlFor } from '../forges/types'
import { ProjectExistsError, createProject } from './service'
import { ensureServiceApp, refreshAppCredential, webhookSecret } from '../forges/apps'
import { forgePublisher } from '../forges/client'
import { consoleUrl } from '../forges/context'

export interface DiscoveryResult {
  repos: number
  created: string[]
  skipped: number
  /** 0.7 (J1) : projets suspendus (dépôt archivé dans la forge) et repris. */
  suspended: string[]
  resumed: string[]
  webhooks: number
  error: string | null
}

function usable(r: ForgeRepo): boolean {
  return !r.archived && !r.empty && !!r.default_branch
}

export async function discoverForge(db: Queryable, forgeIn: ForgeRow, actor: { userId?: number | null, username?: string | null } = {}): Promise<DiscoveryResult> {
  let forge = forgeIn
  const result: DiscoveryResult = { repos: 0, created: [], skipped: 0, suspended: [], resumed: [], webhooks: 0, error: null }
  try {
    // J1 : application GitHub → jeton d'installation recopié pour le clonage.
    if (await refreshAppCredential(db, forge)) forge = (await getForge(db, forge.id)) ?? forge
    const client = await openForge(db, forge)
    const repos = await client.listRepos()
    result.repos = repos.length
    const { rows } = await db.query<{ repo_full_name: string }>(
      `SELECT repo_full_name FROM projects WHERE forge_id = $1 AND repo_full_name IS NOT NULL`, [forge.id])
    const known = new Set(rows.map(r => r.repo_full_name.toLowerCase()))
    await syncSuspensions(db, forge, repos, result)
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
          repoUrl: cloneUrlFor(forge.base_url, repo.full_name),
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
    result.webhooks = await ensureWebhooks(db, forge)
    await db.query(`UPDATE forges SET last_discovery_at = now(), last_error = NULL WHERE id = $1`, [forge.id])
    // Livraisons de plus de 30 jours : inutiles contre le rejeu (identifiants uniques par forge).
    await db.query(`DELETE FROM webhook_deliveries WHERE forge_id = $1 AND received_at < now() - interval '30 days'`, [forge.id])
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
    details: {
      forge: forge.name, repos: result.repos, created: result.created.length, skipped: result.skipped,
      suspended: result.suspended.length, resumed: result.resumed.length, webhooks: result.webhooks, error: result.error,
    },
  })
  return result
}

/**
 * J1 : un dépôt archivé dans la forge suspend son projet (plus d'analyse
 * planifiée ni de webhook) ; désarchivé, le projet reprend. Chaque
 * changement est tracé dans l'audit. Un dépôt absent de la liste (droits
 * retirés) ne change rien : la console ne devine pas.
 */
async function syncSuspensions(db: Queryable, forge: ForgeRow, repos: ForgeRepo[], result: DiscoveryResult): Promise<void> {
  const archived = new Map(repos.map(r => [r.full_name.toLowerCase(), r.archived]))
  const { rows } = await db.query<{ id: string, repo_full_name: string, suspended: boolean }>(
    `SELECT id::text, repo_full_name, suspended_at IS NOT NULL AS suspended FROM projects
      WHERE forge_id = $1 AND repo_full_name IS NOT NULL AND archived_at IS NULL`, [forge.id])
  for (const p of rows) {
    const a = archived.get(p.repo_full_name.toLowerCase())
    if (a === undefined || a === p.suspended) continue
    const r = a
      ? await db.query(`UPDATE projects SET suspended_at = now(), suspended_reason = 'forge-archived' WHERE id = $1 AND suspended_at IS NULL`, [p.id])
      : await db.query(`UPDATE projects SET suspended_at = NULL, suspended_reason = NULL WHERE id = $1 AND suspended_reason = 'forge-archived'`, [p.id])
    if (!r.rowCount) continue
    ;(a ? result.suspended : result.resumed).push(p.id)
    await writeAudit(db, {
      actor: { type: 'system' }, action: a ? 'project.suspend' : 'project.resume', outcome: 'success', targetType: 'project', targetId: p.id,
      details: { reason: 'forge-archived', forge: forge.name, repo: p.repo_full_name },
    })
  }
}

/**
 * J1 (Forgejo, GitLab) : webhook signé posé sur chaque dépôt actif, une fois
 * (la forge garde le webhook ; « exists » s'il est déjà là). GitHub : rien,
 * l'application porte le webhook. Sans adresse de console, rien : mode tiré.
 */
async function ensureWebhooks(db: Queryable, forge: ForgeRow): Promise<number> {
  if (forge.kind === 'github' || !forge.credential_id) return 0
  await ensureServiceApp(db, forge, null)
  const url = await consoleUrl()
  const secret = await webhookSecret(db, forge.id)
  if (!url || !secret) return 0
  const { rows } = await db.query<{ repo_full_name: string }>(
    `SELECT repo_full_name FROM projects WHERE forge_id = $1 AND repo_full_name IS NOT NULL AND archived_at IS NULL AND suspended_at IS NULL
      ORDER BY created_at LIMIT 500`, [forge.id])
  const publisher = forgePublisher(await forgeAccessFor(db, forge), { consoleUrl: url })
  let created = 0
  for (const r of rows) {
    const out = await publisher.ensureWebhook(r.repo_full_name, `${url}/api/forges/${forge.id}/webhook`, secret).catch((err: unknown) => {
      // Droits insuffisants ou forge muette : mode tiré pour ce dépôt (jamais le secret dans le journal).
      console.error('[discover] webhook', r.repo_full_name, (err as { code?: string }).code ?? (err as Error)?.message)
      return null
    })
    if (out === 'created') created++
  }
  return created
}

export const DISCOVERY_INTERVAL_MS = 60 * 60 * 1000

/** Forges dont la découverte est due (activée, avec jeton, plus d'une heure). */
export async function dueForges(db: Queryable, now: Date): Promise<ForgeRow[]> {
  const { rows } = await db.query<{ id: string }>(
    `SELECT id::text FROM forges
      WHERE discovery AND (credential_id IS NOT NULL
             OR EXISTS (SELECT 1 FROM forge_apps a WHERE a.forge_id = forges.id AND cardinality(a.installation_ids) > 0))
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
