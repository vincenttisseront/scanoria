// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Profil figé dans le plan d'une analyse (G8, G9, G11, J8). Appelé par le
// worker sous son verrou de dépôt, sans réseau : la configuration du dépôt a
// été lue avant (config/refresh.ts). Le plan garde le profil effectif
// (héritage fusionné), ses verrous et la chaîne : un rejeu l'applique à
// l'identique, et le gate est durci par le plancher figé ici.

import type { ProfileLocks } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { appliedConfig, type AppliedConfig } from '../config/refresh'
import { syncAiOptOut } from './service'
import { profileForSlot, resolveProfile, slotFor, type ProfileSlot, type ProjectProfiles, type PullRequestRef } from './resolve'

export interface PlanProfile {
  id: string
  slug: string
  categories: string[]
  include_modules: string[]
  exclude_modules: string[]
  /** 0.7 : absents d'un plan plus ancien (rejeu à l'identique, sans plancher). */
  level?: string
  chain?: string[]
  locks?: ProfileLocks
  slot?: ProfileSlot
  source?: 'project' | 'explicit' | 'config'
}

interface ScanRef { id: string, project_id: string, trigger: string, profile_id: string, ref?: string, commit_sha?: string | null, pull_request?: unknown }

/** La configuration du dépôt n'a pas encore été lue pour le commit de l'analyse : le plan attend (G11, J8). */
export class RepoConfigPending extends Error {
  constructor() {
    super('repository configuration not yet read for this commit')
    this.name = 'RepoConfigPending'
  }
}

/** Déclencheurs qui ne lisent pas .scanoria.yml (mêmes que config/refresh.ts). */
const NO_CONFIG_TRIGGERS = new Set(['replay', 'trial', 'recorrelate'])

/** Profil effectif de l'analyse, configuration du dépôt comprise ; scans.profile_id suit un profil demandé par le dépôt. */
export async function planProfile(db: Queryable, scan: ScanRef): Promise<{ profile: PlanProfile, config: AppliedConfig['coverage'] }> {
  const pr = await db.query<ProjectProfiles & { config_state: unknown, reads_config: boolean, requested_by: number | null }>(
    `SELECT p.profile_id::text, p.profile_pr_id::text, p.profile_nightly_id::text, p.profile_release_id::text, p.config_state,
            (p.source_kind = 'git' AND p.forge_id IS NOT NULL AND p.repo_full_name IS NOT NULL) AS reads_config,
            (SELECT s.requested_by FROM scans s WHERE s.id = $2) AS requested_by
       FROM projects p WHERE p.id = $1`,
    [scan.project_id, scan.id])
  const project = pr.rows[0]!
  // La configuration appliquée est celle du commit analysé, jamais celle d'une autre analyse en file.
  if (project.reads_config && !NO_CONFIG_TRIGGERS.has(scan.trigger)) {
    const key = scan.commit_sha ?? scan.ref
    const state = project.config_state as { read_key?: unknown } | null
    if (!state || state.read_key !== key) throw new RepoConfigPending()
  }
  const pullRequest = scan.pull_request && typeof scan.pull_request === 'object' ? scan.pull_request as PullRequestRef : null
  const slot = slotFor(scan.trigger, pullRequest)
  const bySlot = profileForSlot(project, slot)
  let profileId = scan.profile_id
  let source: 'explicit' | 'config' = 'explicit'
  const applied = scan.trigger === 'trial' ? { profileSlug: null, coverage: null } : appliedConfig(project.config_state, slot)
  // J8 : le dépôt choisit le profil de l'emplacement, sauf profil demandé explicitement (API, console).
  if (applied.profileSlug && scan.profile_id === bySlot) {
    const c = await db.query<{ id: string }>('SELECT id::text FROM profiles WHERE slug = $1 AND archived_at IS NULL', [applied.profileSlug])
    if (c.rows[0]) {
      profileId = c.rows[0].id
      source = 'config'
      if (profileId !== scan.profile_id) await db.query('UPDATE scans SET profile_id = $2 WHERE id = $1', [scan.id, profileId])
    }
  }
  // Un profil choisi par le dépôt ou par un appel non humain (jeton d'API, CI) ne peut qu'ajouter au profil
  // de l'emplacement ; pour une release, même un choix humain. Seul un utilisateur de la console réduit le
  // périmètre d'une analyse manuelle (choix tracé, verdict de cette analyse seulement).
  const additive = source === 'config' || project.requested_by === null || slot === 'release'
  const r = await resolveProfile(db, scan.project_id, scan.trigger, { pullRequest, profileId, source, additive })
  const e = r.effective
  // « Aucun envoi à l'IA » du profil effectif : imposé au projet avant tout envoi lié à cette analyse.
  if (e.locks.ai_opt_out) await syncAiOptOut(db, scan.project_id)
  return {
    profile: {
      id: e.id,
      slug: e.slug,
      categories: e.categories,
      include_modules: e.include_modules,
      exclude_modules: e.exclude_modules,
      level: e.level,
      chain: e.chain.map(c => c.slug),
      locks: e.locks,
      slot,
      source: r.chosen.source,
    },
    config: applied.coverage,
  }
}
