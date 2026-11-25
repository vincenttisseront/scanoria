// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Résolution du profil d'une analyse (0.7, contrat 29).
// - Choix G9 : une PR prend profile_pr_id, l'analyse nocturne (planifiée)
//   profile_nightly_id, une release profile_release_id, tout autre
//   déclencheur profile_id ; un champ vide renvoie à profile_id.
// - Profil effectif G8 : héritage fusionné de la racine (entreprise) jusqu'au
//   profil choisi, puis verrous appliqués (catégories et modules exigés
//   ajoutés, jamais exclus).
// - Un profil demandé autrement (paramètre de la CI, .scanoria.yml) n'échappe
//   jamais aux verrous : ceux du profil que G9 aurait choisi s'y ajoutent.
// Le résultat est figé dans le plan (G11) par le worker.

import type { ProfileLocks, ScanTrigger } from '#shared/analysis'
import type { Queryable } from '../utils/db'
import { mergeAll, mergeLocks, parseLocks } from './locks'
import type { ProfileLevel } from './service'

export const PROFILE_SLOTS = ['pr', 'nightly', 'release', 'default'] as const
export type ProfileSlot = (typeof PROFILE_SLOTS)[number]

/** Colonne de projects pour chaque déclencheur (G9). */
export const SLOT_COLUMN: Record<ProfileSlot, 'profile_pr_id' | 'profile_nightly_id' | 'profile_release_id' | 'profile_id'> = {
  pr: 'profile_pr_id',
  nightly: 'profile_nightly_id',
  release: 'profile_release_id',
  default: 'profile_id',
}

/** Défauts de l'entreprise pour un nouveau projet (principe 8). */
export const SLOT_DEFAULT_SLUG: Record<Exclude<ProfileSlot, 'default'>, string> = {
  pr: 'rapide',
  nightly: 'complet',
  release: 'release',
}

export interface PullRequestRef { number: number, base_sha?: string, [k: string]: unknown }

/** Emplacement G9 d'une analyse selon son déclencheur. */
export function slotFor(trigger: ScanTrigger | string, pullRequest?: PullRequestRef | null): ProfileSlot {
  if (pullRequest) return 'pr'
  if (trigger === 'release') return 'release'
  if (trigger === 'schedule') return 'nightly'
  return 'default'
}

export interface ProjectProfiles {
  profile_id: string
  profile_pr_id: string | null
  profile_nightly_id: string | null
  profile_release_id: string | null
}

/** Profil retenu pour un emplacement : son champ, sinon profile_id. */
export function profileForSlot(p: ProjectProfiles, slot: ProfileSlot): string {
  return p[SLOT_COLUMN[slot]] ?? p.profile_id
}

export interface EffectiveProfile {
  id: string
  slug: string
  level: ProfileLevel
  /** Chaîne de la racine jusqu'au profil (slugs, pour l'affichage et l'audit). */
  chain: { id: string, slug: string, level: ProfileLevel }[]
  categories: string[]
  include_modules: string[]
  exclude_modules: string[]
  /** Verrous fusionnés de la chaîne (et du profil G9 remplacé, le cas échéant). */
  locks: ProfileLocks
  /** Jeux de règles retenus (chantier A, contrat 34) : un enfant remplace l'épinglage du parent. */
  rulesets: { ruleset_id: string, slug: string, engine: string, pinned_version: number | null }[]
}

interface ChainRow {
  id: string
  slug: string
  level: ProfileLevel
  parent_id: string | null
  categories: string[]
  include_modules: string[]
  exclude_modules: string[]
  locks: unknown
  rulesets: { ruleset_id: string, slug: string, engine: string, pinned_version: number | null }[]
}

export class ProfileResolutionError extends Error {
  constructor(readonly code: 'E_PROFILE_NOT_FOUND' | 'E_PROFILE_CHAIN') {
    super(code)
    this.name = 'ProfileResolutionError'
  }
}

async function chainRows(db: Queryable, profileId: string): Promise<ChainRow[]> {
  const res = await db.query<ChainRow & { depth: number }>(
    `WITH RECURSIVE chain AS (
       SELECT id, parent_id, 1 AS depth FROM profiles WHERE id = $1
       UNION ALL
       SELECT p.id, p.parent_id, c.depth + 1 FROM profiles p JOIN chain c ON p.id = c.parent_id WHERE c.depth < 5)
     SELECT p.id::text, p.slug, p.level, p.parent_id::text, p.categories, p.include_modules, p.exclude_modules, p.locks, c.depth,
            COALESCE((SELECT json_agg(json_build_object('ruleset_id', r.id, 'slug', r.slug, 'engine', r.engine, 'pinned_version', pr.pinned_version)
                                       ORDER BY r.slug)
                        FROM profile_rulesets pr JOIN rulesets r ON r.id = pr.ruleset_id
                       WHERE pr.profile_id = p.id AND r.archived_at IS NULL), '[]'::json) AS rulesets
       FROM chain c JOIN profiles p ON p.id = c.id ORDER BY c.depth DESC`,
    [profileId],
  )
  if (!res.rows.length) throw new ProfileResolutionError('E_PROFILE_NOT_FOUND')
  const ids = new Set(res.rows.map(r => r.id))
  if (res.rows.length > 3 || ids.size !== res.rows.length || res.rows[0]!.parent_id !== null) throw new ProfileResolutionError('E_PROFILE_CHAIN')
  return res.rows
}

/**
 * Fusion pure d'une chaîne (racine d'abord) : catégories et inclusions
 * s'additionnent ; une exclusion d'un niveau inférieur retire une inclusion
 * héritée et inversement ; puis les verrous s'appliquent.
 */
export function mergeChain(rows: ChainRow[], extraLocks?: ProfileLocks): EffectiveProfile {
  const categories = new Set<string>()
  const include = new Set<string>()
  const exclude = new Set<string>()
  const rulesets = new Map<string, EffectiveProfile['rulesets'][number]>()
  for (const r of rows) {
    for (const c of r.categories) categories.add(c)
    for (const m of r.include_modules) {
      include.add(m)
      exclude.delete(m)
    }
    for (const m of r.exclude_modules) {
      exclude.add(m)
      include.delete(m)
    }
    for (const rs of r.rulesets) rulesets.set(rs.ruleset_id, rs)
  }
  let locks = mergeAll(rows.map(r => parseLocks(r.locks)))
  if (extraLocks) locks = mergeLocks(locks, extraLocks)
  for (const c of locks.required_categories) categories.add(c)
  for (const m of locks.required_modules) {
    include.add(m)
    exclude.delete(m)
  }
  const self = rows[rows.length - 1]!
  return {
    id: self.id,
    slug: self.slug,
    level: self.level,
    chain: rows.map(r => ({ id: r.id, slug: r.slug, level: r.level })),
    // Ordre d'origine conservé (racine d'abord, puis exigences) : un plan d'un profil sans parent reste identique.
    categories: [...categories],
    include_modules: [...include],
    exclude_modules: [...exclude],
    locks,
    rulesets: [...rulesets.values()].sort((a, b) => a.slug.localeCompare(b.slug)),
  }
}

/** Profil effectif d'un profil donné (G8), éventuellement sous les verrous d'un autre profil. */
export async function effectiveProfile(db: Queryable, profileId: string, opts: { alsoLockedBy?: string | null } = {}): Promise<EffectiveProfile> {
  const rows = await chainRows(db, profileId)
  let extra: ProfileLocks | undefined
  if (opts.alsoLockedBy && opts.alsoLockedBy !== profileId) {
    extra = mergeAll((await chainRows(db, opts.alsoLockedBy)).map(r => parseLocks(r.locks)))
  }
  return mergeChain(rows, extra)
}

export interface ResolvedProfile {
  /** Profil choisi pour l'analyse (enregistré dans scans.profile_id). */
  chosen: { id: string, slug: string, slot: ProfileSlot, source: 'project' | 'explicit' | 'config' }
  effective: EffectiveProfile
}

export interface ResolveOptions {
  pullRequest?: PullRequestRef | null
  /** Profil imposé (paramètre profile de l'API, profil déjà choisi d'une analyse en file). */
  profileId?: string | null
  /** Origine de profileId : « explicit » (API, console) ou « config » (.scanoria.yml). */
  source?: 'explicit' | 'config'
}

/** Contrat 29 : profil choisi (G9) et profil effectif (G8) d'une analyse. */
export async function resolveProfile(db: Queryable, projectId: string, trigger: ScanTrigger | string, opts: ResolveOptions = {}): Promise<ResolvedProfile> {
  const p = await db.query<ProjectProfiles>(
    `SELECT profile_id::text, profile_pr_id::text, profile_nightly_id::text, profile_release_id::text FROM projects WHERE id = $1`, [projectId])
  const project = p.rows[0]
  if (!project) throw new ProfileResolutionError('E_PROFILE_NOT_FOUND')
  const slot = slotFor(trigger, opts.pullRequest)
  const bySlot = profileForSlot(project, slot)
  const chosenId = opts.profileId ?? bySlot
  const effective = await effectiveProfile(db, chosenId, { alsoLockedBy: bySlot })
  return {
    chosen: { id: chosenId, slug: effective.slug, slot, source: opts.profileId && opts.profileId !== bySlot ? (opts.source ?? 'explicit') : 'project' },
    effective,
  }
}

/** Défauts G9 d'un nouveau projet : PR → rapide, nuit → complet, release → release. */
export async function applySlotDefaults(db: Queryable, projectId: string): Promise<void> {
  await db.query(
    `UPDATE projects p
        SET profile_pr_id = COALESCE(p.profile_pr_id, (SELECT id FROM profiles WHERE slug = $2 AND builtin AND archived_at IS NULL)),
            profile_nightly_id = COALESCE(p.profile_nightly_id, (SELECT id FROM profiles WHERE slug = $3 AND builtin AND archived_at IS NULL)),
            profile_release_id = COALESCE(p.profile_release_id, (SELECT id FROM profiles WHERE slug = $4 AND builtin AND archived_at IS NULL))
      WHERE p.id = $1`,
    [projectId, SLOT_DEFAULT_SLUG.pr, SLOT_DEFAULT_SLUG.nightly, SLOT_DEFAULT_SLUG.release])
}
