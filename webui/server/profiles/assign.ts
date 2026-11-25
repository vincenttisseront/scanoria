// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Profils d'un projet par déclencheur (G9) : défaut, PR, nuit, release. Un
// opérateur choisit librement tant que les verrous restent au moins aussi
// stricts ; remplacer un profil verrouillé par un profil plus souple est
// réservé à l'administrateur (comme le changement de quality gate).

import { z } from 'zod'
import type { ProfileLocks } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { compareStrictness } from './locks'
import { aiOptOutLocked, syncAiOptOut } from './service'
import { PROFILE_SLOTS, SLOT_COLUMN, effectiveProfile, profileForSlot, type ProfileSlot, type ProjectProfiles } from './resolve'
import { appliedConfig, parseConfigState } from '../config/refresh'

export const projectProfilesSchema = z.strictObject({
  default: z.string().uuid().optional(),
  pr: z.string().uuid().nullable().optional(),
  nightly: z.string().uuid().nullable().optional(),
  release: z.string().uuid().nullable().optional(),
})
export type ProjectProfilesUpdate = z.infer<typeof projectProfilesSchema>

/** Le second jeu de verrous est-il au moins aussi strict que le premier ? */
export function locksCover(current: ProfileLocks, next: ProfileLocks): boolean {
  if (current.ai_opt_out && !next.ai_opt_out) return false
  if (!current.required_categories.every(c => next.required_categories.includes(c))) return false
  if (!current.required_modules.every(m => next.required_modules.includes(m))) return false
  for (const [k, v] of Object.entries(current.gate_floor)) {
    const n = (next.gate_floor as Record<string, unknown>)[k]
    if (n === undefined || compareStrictness(k as never, n, v) > 0) return false
  }
  return true
}

export interface ProjectProfilesView {
  slots: Record<ProfileSlot, { profile_id: string | null, effective_id: string, slug: string, chain: string[], locks: ProfileLocks, from_config: string | null }>
  ai_opt_out: boolean
  ai_opt_out_locked: boolean
  config_state: ReturnType<typeof parseConfigState>
}

export async function projectProfilesView(db: Queryable, projectId: string): Promise<ProjectProfilesView | null> {
  const r = await db.query<ProjectProfiles & { ai_opt_out: boolean, config_state: unknown }>(
    `SELECT profile_id::text, profile_pr_id::text, profile_nightly_id::text, profile_release_id::text, ai_opt_out, config_state
       FROM projects WHERE id = $1`, [projectId])
  const p = r.rows[0]
  if (!p) return null
  const slots = {} as ProjectProfilesView['slots']
  for (const slot of PROFILE_SLOTS) {
    const id = profileForSlot(p, slot)
    const e = await effectiveProfile(db, id)
    slots[slot] = {
      profile_id: p[SLOT_COLUMN[slot]], effective_id: id, slug: e.slug, chain: e.chain.map(c => c.slug), locks: e.locks,
      from_config: appliedConfig(p.config_state, slot).profileSlug,
    }
  }
  return { slots, ai_opt_out: p.ai_opt_out, ai_opt_out_locked: await aiOptOutLocked(db, projectId), config_state: parseConfigState(p.config_state) }
}

export class AssignError extends Error {
  constructor(readonly code: 'E_PROFILE_NOT_FOUND' | 'E_PROFILE_ARCHIVED' | 'E_PROFILE_LOOSER', readonly slot: ProfileSlot) {
    super(code)
  }
}

/**
 * Applique les profils par déclencheur. Renvoie les emplacements changés et
 * ceux dont les verrous s'assouplissent (l'appelant exige alors le rôle admin).
 */
export async function assignProfiles(db: Queryable, projectId: string, body: ProjectProfilesUpdate, opts: { admin: boolean }): Promise<{ changed: Record<string, { from: string | null, to: string | null }>, imposed: boolean }> {
  const r = await db.query<ProjectProfiles>(
    `SELECT profile_id::text, profile_pr_id::text, profile_nightly_id::text, profile_release_id::text FROM projects WHERE id = $1 FOR UPDATE`, [projectId])
  const p = r.rows[0]!
  const changed: Record<string, { from: string | null, to: string | null }> = {}
  const next: ProjectProfiles = { ...p }
  for (const slot of PROFILE_SLOTS) {
    const v = body[slot]
    if (v === undefined) continue
    const col = SLOT_COLUMN[slot]
    if (v !== null) {
      const ok = await db.query<{ archived: boolean }>('SELECT archived_at IS NOT NULL AS archived FROM profiles WHERE id = $1', [v])
      if (!ok.rows[0]) throw new AssignError('E_PROFILE_NOT_FOUND', slot)
      if (ok.rows[0].archived) throw new AssignError('E_PROFILE_ARCHIVED', slot)
    }
    if ((p[col] ?? null) === v) continue
    ;(next as unknown as Record<string, string | null>)[col] = v
    changed[slot] = { from: p[col] ?? null, to: v }
  }
  // Verrous : chaque emplacement effectif doit rester au moins aussi strict, sauf pour un administrateur.
  if (!opts.admin) {
    for (const slot of PROFILE_SLOTS) {
      const before = profileForSlot(p, slot)
      const after = profileForSlot(next, slot)
      if (before === after) continue
      const [b, a] = await Promise.all([effectiveProfile(db, before), effectiveProfile(db, after)])
      if (!locksCover(b.locks, a.locks)) throw new AssignError('E_PROFILE_LOOSER', slot)
    }
  }
  if (Object.keys(changed).length) {
    await db.query(
      `UPDATE projects SET profile_id = $2, profile_pr_id = $3, profile_nightly_id = $4, profile_release_id = $5 WHERE id = $1`,
      [projectId, next.profile_id, next.profile_pr_id, next.profile_nightly_id, next.profile_release_id])
  }
  const imposed = (await syncAiOptOut(db, projectId)).length > 0
  return { changed, imposed }
}

/**
 * Changement du profil par défaut par la route de modification d'un projet
 * (PATCH /api/projects/:id) : mêmes règles que assignProfiles (profil
 * archivé refusé, verrous assouplis réservés à l'administrateur).
 */
export async function checkDefaultProfileChange(db: Queryable, projectId: string, to: string, opts: { admin: boolean }): Promise<void> {
  const r = await db.query<ProjectProfiles>(
    `SELECT profile_id::text, profile_pr_id::text, profile_nightly_id::text, profile_release_id::text FROM projects WHERE id = $1`, [projectId])
  const p = r.rows[0]
  if (!p || p.profile_id === to) return
  const ok = await db.query<{ archived: boolean }>('SELECT archived_at IS NOT NULL AS archived FROM profiles WHERE id = $1', [to])
  if (!ok.rows[0]) return // signalé par la validation habituelle (E_VALIDATION)
  if (ok.rows[0].archived) throw new AssignError('E_PROFILE_ARCHIVED', 'default')
  if (opts.admin) return
  const next = { ...p, profile_id: to }
  for (const slot of PROFILE_SLOTS) {
    const before = profileForSlot(p, slot)
    const after = profileForSlot(next, slot)
    if (before === after) continue
    const [b, a] = await Promise.all([effectiveProfile(db, before), effectiveProfile(db, after)])
    if (!locksCover(b.locks, a.locks)) throw new AssignError('E_PROFILE_LOOSER', slot)
  }
}
