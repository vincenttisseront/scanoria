// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Profils personnalisés (0.7, G8) : création, modification et archivage, en
// hiérarchie entreprise → équipe → projet. Le contrôle de la hiérarchie est
// fait ici (message clair) et en base (déclencheur profiles_hierarchy, 014) :
// un parent a toujours un niveau strictement supérieur, donc aucun cycle.
// Un profil enfant ne peut jamais assouplir les verrous hérités (contrat 28).

import { z } from 'zod'
import { CATEGORIES, ProfileLocks, SLUG_RE } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import type { Queryable } from '../utils/db'
import { EMPTY_LOCKS, findLoosening, mergeAll, parseLocks, type LockViolation } from './locks'

export const PROFILE_LEVELS = ['enterprise', 'team', 'project'] as const
export type ProfileLevel = (typeof PROFILE_LEVELS)[number]

/** Niveaux admis pour le parent d'un profil (vide : aucun parent). */
export const PARENT_LEVELS: Record<ProfileLevel, ProfileLevel[]> = {
  enterprise: [],
  team: ['enterprise'],
  project: ['enterprise', 'team'],
}

const moduleId = z.string().regex(MODULE_ID_RE)
/** Caractère de contrôle autre que tabulation et retour à la ligne. */
export function hasControlChars(v: string): boolean {
  for (const ch of v) {
    const c = ch.codePointAt(0)!
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f) return true
  }
  return false
}

const description = z.string().trim().max(2000).refine(v => !hasControlChars(v), { message: 'control characters' })

export const profileRulesetSchema = z.strictObject({
  ruleset_id: z.string().uuid(),
  pinned_version: z.number().int().min(1).nullable().default(null),
})

const profileBody = {
  categories: z.array(z.enum(CATEGORIES)).max(32),
  include_modules: z.array(moduleId).max(64),
  exclude_modules: z.array(moduleId).max(64),
  description: description.nullable(),
  locks: ProfileLocks,
  rulesets: z.array(profileRulesetSchema).max(32),
}

export const profileCreateSchema = z.strictObject({
  slug: z.string().regex(SLUG_RE),
  level: z.enum(PROFILE_LEVELS),
  parent_id: z.string().uuid().nullable().default(null),
  categories: profileBody.categories.default([]),
  include_modules: profileBody.include_modules.default([]),
  exclude_modules: profileBody.exclude_modules.default([]),
  description: profileBody.description.default(null),
  locks: profileBody.locks.default(EMPTY_LOCKS),
  rulesets: profileBody.rulesets.default([]),
})
export type ProfileCreate = z.infer<typeof profileCreateSchema>

export const profileUpdateSchema = z.strictObject({
  level: z.enum(PROFILE_LEVELS).optional(),
  parent_id: z.string().uuid().nullable().optional(),
  categories: profileBody.categories.optional(),
  include_modules: profileBody.include_modules.optional(),
  exclude_modules: profileBody.exclude_modules.optional(),
  description: profileBody.description.optional(),
  locks: profileBody.locks.optional(),
  rulesets: profileBody.rulesets.optional(),
})
export type ProfileUpdate = z.infer<typeof profileUpdateSchema>

export interface ProfileRulesetRow { ruleset_id: string, slug: string, engine: string, pinned_version: number | null }

export interface ProfileRow {
  id: string
  slug: string
  builtin: boolean
  level: ProfileLevel
  parent_id: string | null
  parent_slug: string | null
  categories: string[]
  include_modules: string[]
  exclude_modules: string[]
  description: string | null
  locks: ProfileLocks
  rulesets: ProfileRulesetRow[]
  archived_at: string | null
  updated_at: string
  updated_by_username: string | null
  /** Projets actifs qui utilisent le profil (défaut ou déclencheur). */
  projects: number
  children: number
}

const ts = (col: string) => `to_char(${col} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`

const COLUMNS = `p.id::text, p.slug, p.builtin, p.level, p.parent_id::text, pp.slug AS parent_slug,
  p.categories, p.include_modules, p.exclude_modules, p.description, p.locks,
  ${ts('p.archived_at')} AS archived_at, ${ts('p.updated_at')} AS updated_at, u.username AS updated_by_username,
  (SELECT count(*)::int FROM projects x WHERE x.archived_at IS NULL
      AND p.id IN (x.profile_id, x.profile_pr_id, x.profile_nightly_id, x.profile_release_id)) AS projects,
  (SELECT count(*)::int FROM profiles c WHERE c.parent_id = p.id AND c.archived_at IS NULL) AS children,
  COALESCE((SELECT json_agg(json_build_object('ruleset_id', r.id, 'slug', r.slug, 'engine', r.engine, 'pinned_version', pr.pinned_version)
                             ORDER BY r.slug)
              FROM profile_rulesets pr JOIN rulesets r ON r.id = pr.ruleset_id WHERE pr.profile_id = p.id), '[]'::json) AS rulesets`

const FROM = 'FROM profiles p LEFT JOIN profiles pp ON pp.id = p.parent_id LEFT JOIN users u ON u.id = p.updated_by'

function normalize(row: ProfileRow): ProfileRow {
  return { ...row, locks: parseLocks(row.locks) }
}

export async function listProfiles(db: Queryable, opts: { archived?: boolean } = {}): Promise<ProfileRow[]> {
  const res = await db.query<ProfileRow>(
    `SELECT ${COLUMNS} ${FROM} WHERE ($1::boolean OR p.archived_at IS NULL)
      ORDER BY CASE p.level WHEN 'enterprise' THEN 0 WHEN 'team' THEN 1 ELSE 2 END, p.builtin DESC, p.slug`,
    [opts.archived ?? false],
  )
  return res.rows.map(normalize)
}

export async function getProfile(db: Queryable, id: string): Promise<ProfileRow | null> {
  const res = await db.query<ProfileRow>(`SELECT ${COLUMNS} ${FROM} WHERE p.id = $1`, [id])
  return res.rows[0] ? normalize(res.rows[0]) : null
}

export async function getProfileBySlug(db: Queryable, slug: string): Promise<ProfileRow | null> {
  const res = await db.query<ProfileRow>(`SELECT ${COLUMNS} ${FROM} WHERE p.slug = $1`, [slug])
  return res.rows[0] ? normalize(res.rows[0]) : null
}

export interface ChainLink { id: string, slug: string, level: ProfileLevel, locks: ProfileLocks, archived: boolean }

/**
 * Chaîne d'un profil, de la racine (entreprise) jusqu'à lui. La hiérarchie a
 * au plus trois niveaux ; une chaîne plus longue ou bouclée (base corrompue)
 * est coupée et signalée par null.
 */
export async function profileChain(db: Queryable, id: string): Promise<ChainLink[] | null> {
  const res = await db.query<{ id: string, slug: string, level: ProfileLevel, locks: unknown, archived: boolean, parent_id: string | null }>(
    `WITH RECURSIVE chain AS (
       SELECT id, slug, level, locks, archived_at IS NOT NULL AS archived, parent_id, 1 AS depth FROM profiles WHERE id = $1
       UNION ALL
       SELECT p.id, p.slug, p.level, p.locks, p.archived_at IS NOT NULL, p.parent_id, c.depth + 1
         FROM profiles p JOIN chain c ON p.id = c.parent_id WHERE c.depth < 5)
     SELECT id::text, slug, level, locks, archived, parent_id::text FROM chain ORDER BY depth DESC`,
    [id],
  )
  if (!res.rows.length) return null
  const ids = new Set(res.rows.map(r => r.id))
  if (res.rows.length > 3 || ids.size !== res.rows.length || res.rows[0]!.parent_id !== null) return null
  return res.rows.map(r => ({ id: r.id, slug: r.slug, level: r.level, locks: parseLocks(r.locks), archived: r.archived }))
}

export type ProfileErrorCode
  = | 'E_PROFILE_SLUG_TAKEN' | 'E_PROFILE_PARENT' | 'E_PROFILE_LEVEL' | 'E_PROFILE_CYCLE' | 'E_PROFILE_LOCKED'
    | 'E_PROFILE_BUILTIN' | 'E_PROFILE_IN_USE' | 'E_PROFILE_CHILDREN' | 'E_PROFILE_ARCHIVED' | 'E_PROFILE_RULESET'

export class ProfileError extends Error {
  constructor(readonly code: ProfileErrorCode, readonly status = 400, readonly details: Record<string, unknown> = {}) {
    super(code)
    this.name = 'ProfileError'
  }
}

/** Verrous hérités par un profil placé sous parentId (fusion de toute la chaîne du parent). */
export async function inheritedLocks(db: Queryable, parentId: string | null): Promise<ProfileLocks> {
  if (!parentId) return EMPTY_LOCKS
  const chain = await profileChain(db, parentId)
  if (!chain) throw new ProfileError('E_PROFILE_CYCLE')
  return mergeAll(chain.map(c => c.locks))
}

interface Candidate {
  id: string | null
  level: ProfileLevel
  parent_id: string | null
  exclude_modules: string[]
  locks: ProfileLocks
}

/** Contrôles applicatifs d'un profil avant enregistrement : parent, niveau, cycle, verrous. */
async function checkCandidate(db: Queryable, c: Candidate): Promise<void> {
  const allowed = PARENT_LEVELS[c.level]
  if (c.parent_id === null) {
    if (allowed.length) throw new ProfileError('E_PROFILE_PARENT')
  }
  else {
    if (!allowed.length) throw new ProfileError('E_PROFILE_PARENT')
    const parent = await db.query<{ level: ProfileLevel, archived: boolean }>(
      'SELECT level, archived_at IS NOT NULL AS archived FROM profiles WHERE id = $1', [c.parent_id])
    const p = parent.rows[0]
    if (!p) throw new ProfileError('E_PROFILE_PARENT', 404)
    if (p.archived) throw new ProfileError('E_PROFILE_ARCHIVED', 409)
    if (!allowed.includes(p.level)) throw new ProfileError('E_PROFILE_LEVEL', 400, { parent_level: p.level })
    if (c.id) {
      const chain = await profileChain(db, c.parent_id)
      if (!chain || chain.some(x => x.id === c.id)) throw new ProfileError('E_PROFILE_CYCLE')
    }
  }
  if (c.id) {
    // Les enfants doivent rester d'un niveau inférieur.
    const kids = await db.query<{ level: ProfileLevel }>('SELECT level FROM profiles WHERE parent_id = $1', [c.id])
    if (kids.rows.some(k => !PARENT_LEVELS[k.level].includes(c.level))) throw new ProfileError('E_PROFILE_CHILDREN', 409)
  }
  const violations: LockViolation[] = findLoosening(await inheritedLocks(db, c.parent_id), {
    locks: c.locks, exclude_modules: c.exclude_modules,
  })
  // Le profil lui-même ne peut pas exclure un module qu'il exige.
  for (const m of c.exclude_modules) {
    if (c.locks.required_modules.includes(m)) violations.push({ field: 'exclude_modules', locked: m, requested: m })
  }
  if (violations.length) throw new ProfileError('E_PROFILE_LOCKED', 409, { violations })
}

/** Les verrous des descendants ne peuvent pas assouplir ceux d'un parent modifié. */
async function checkDescendants(db: Queryable, id: string): Promise<void> {
  const kids = await db.query<{ id: string, slug: string, exclude_modules: string[], locks: unknown }>(
    `WITH RECURSIVE d AS (SELECT id, slug, exclude_modules, locks, 1 AS depth FROM profiles WHERE parent_id = $1
       UNION ALL SELECT p.id, p.slug, p.exclude_modules, p.locks, d.depth + 1 FROM profiles p JOIN d ON p.parent_id = d.id WHERE d.depth < 4)
     SELECT id::text, slug, exclude_modules, locks FROM d`, [id])
  for (const k of kids.rows) {
    const chain = await profileChain(db, k.id)
    if (!chain) throw new ProfileError('E_PROFILE_CYCLE')
    const inherited = mergeAll(chain.slice(0, -1).map(c => c.locks))
    const v = findLoosening(inherited, { locks: parseLocks(k.locks), exclude_modules: k.exclude_modules })
    if (v.length) throw new ProfileError('E_PROFILE_LOCKED', 409, { violations: v, profile: k.slug })
  }
}

async function setRulesets(db: Queryable, profileId: string, rulesets: z.infer<typeof profileRulesetSchema>[]): Promise<void> {
  const ids = [...new Set(rulesets.map(r => r.ruleset_id))]
  if (ids.length !== rulesets.length) throw new ProfileError('E_PROFILE_RULESET')
  if (ids.length) {
    const found = await db.query<{ id: string, max: number | null }>(
      `SELECT r.id::text, (SELECT max(version) FROM ruleset_versions v WHERE v.ruleset_id = r.id) AS max
         FROM rulesets r WHERE r.id = ANY($1::uuid[]) AND r.archived_at IS NULL`, [ids])
    const max = new Map(found.rows.map(r => [r.id, r.max]))
    for (const r of rulesets) {
      if (!max.has(r.ruleset_id)) throw new ProfileError('E_PROFILE_RULESET', 404)
      if (r.pinned_version !== null && (max.get(r.ruleset_id) ?? 0) < r.pinned_version) throw new ProfileError('E_PROFILE_RULESET')
    }
  }
  await db.query('DELETE FROM profile_rulesets WHERE profile_id = $1', [profileId])
  for (const r of rulesets) {
    await db.query('INSERT INTO profile_rulesets (profile_id, ruleset_id, pinned_version) VALUES ($1, $2, $3)',
      [profileId, r.ruleset_id, r.pinned_version])
  }
}

function mapDbError(err: unknown): never {
  const e = err as { code?: string, constraint?: string }
  if (e.code === '23505') throw new ProfileError('E_PROFILE_SLUG_TAKEN', 409)
  if (e.code === '23514' && (e.constraint === 'profiles_parent_level' || e.constraint === 'profiles_level_parent')) throw new ProfileError('E_PROFILE_LEVEL')
  if (e.code === '23514' && e.constraint === 'profiles_not_own_parent') throw new ProfileError('E_PROFILE_CYCLE')
  throw err
}

const uniq = (xs: string[]) => [...new Set(xs)]

export async function createProfile(db: Queryable, input: ProfileCreate, userId: number | null): Promise<ProfileRow> {
  await checkCandidate(db, {
    id: null, level: input.level, parent_id: input.parent_id, exclude_modules: input.exclude_modules,
    locks: input.locks,
  })
  let id: string
  try {
    const r = await db.query<{ id: string }>(
      `INSERT INTO profiles (slug, builtin, level, parent_id, categories, include_modules, exclude_modules, description, locks, updated_by)
       VALUES ($1, false, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id::text`,
      [input.slug, input.level, input.parent_id, uniq(input.categories), uniq(input.include_modules), uniq(input.exclude_modules),
        input.description || null, JSON.stringify(input.locks), userId])
    id = r.rows[0]!.id
  }
  catch (err) {
    mapDbError(err)
  }
  await setRulesets(db, id, input.rulesets)
  return (await getProfile(db, id))!
}

export async function updateProfile(db: Queryable, id: string, patch: ProfileUpdate, userId: number | null): Promise<{ before: ProfileRow, after: ProfileRow }> {
  const before = await getProfile(db, id)
  if (!before) throw new ProfileError('E_PROFILE_PARENT', 404)
  if (before.archived_at) throw new ProfileError('E_PROFILE_ARCHIVED', 409)
  if (before.builtin && ((patch.level && patch.level !== before.level) || (patch.parent_id !== undefined && patch.parent_id !== before.parent_id))) {
    throw new ProfileError('E_PROFILE_BUILTIN', 409)
  }
  const next = {
    level: patch.level ?? before.level,
    parent_id: patch.parent_id !== undefined ? patch.parent_id : before.parent_id,
    categories: uniq(patch.categories ?? before.categories),
    include_modules: uniq(patch.include_modules ?? before.include_modules),
    exclude_modules: uniq(patch.exclude_modules ?? before.exclude_modules),
    description: patch.description !== undefined ? (patch.description || null) : before.description,
    locks: patch.locks ?? before.locks,
  }
  await checkCandidate(db, {
    id, level: next.level, parent_id: next.parent_id, exclude_modules: next.exclude_modules,
    locks: next.locks,
  })
  try {
    await db.query(
      `UPDATE profiles SET level = $2, parent_id = $3, categories = $4, include_modules = $5, exclude_modules = $6,
              description = $7, locks = $8, updated_at = now(), updated_by = $9 WHERE id = $1`,
      [id, next.level, next.parent_id, next.categories, next.include_modules, next.exclude_modules,
        next.description, JSON.stringify(next.locks), userId])
  }
  catch (err) {
    mapDbError(err)
  }
  await checkDescendants(db, id)
  if (patch.rulesets) await setRulesets(db, id, patch.rulesets)
  return { before, after: (await getProfile(db, id))! }
}

/** Archivage : jamais un profil intégré, ni un profil utilisé par un projet ou parent d'un profil actif. */
export async function archiveProfile(db: Queryable, id: string, archived: boolean, userId: number | null): Promise<ProfileRow> {
  const p = await getProfile(db, id)
  if (!p) throw new ProfileError('E_PROFILE_PARENT', 404)
  if (archived) {
    if (p.builtin) throw new ProfileError('E_PROFILE_BUILTIN', 409)
    if (p.projects > 0) throw new ProfileError('E_PROFILE_IN_USE', 409, { projects: p.projects })
    if (p.children > 0) throw new ProfileError('E_PROFILE_CHILDREN', 409, { children: p.children })
  }
  else if (p.parent_id) {
    const parent = await getProfile(db, p.parent_id)
    if (parent?.archived_at) throw new ProfileError('E_PROFILE_ARCHIVED', 409)
  }
  await db.query(
    `UPDATE profiles SET archived_at = CASE WHEN $2 THEN COALESCE(archived_at, now()) END, updated_at = now(), updated_by = $3 WHERE id = $1`,
    [id, archived, userId])
  return (await getProfile(db, id))!
}

/** Ids des profils dont la chaîne impose « aucun envoi à l'IA ». */
const AI_LOCKED_PROFILES = `WITH RECURSIVE locked AS (
    SELECT id FROM profiles WHERE (locks->>'ai_opt_out')::boolean IS TRUE
    UNION SELECT p.id FROM profiles p JOIN locked l ON p.parent_id = l.id)
  SELECT id FROM locked`

/**
 * « Aucun envoi à l'IA » imposé (G8, § 3.5) : un projet dont un profil (défaut
 * ou déclencheur, ou profil choisi pour une de ses analyses : API, .scanoria.yml)
 * est sous un verrou ai_opt_out passe à ai_opt_out = true, durablement. Tous
 * les envois IA (console, relais) lisent cette colonne : le verrou s'applique
 * partout sans autre point de contrôle. Renvoie les projets basculés.
 */
export async function syncAiOptOut(db: Queryable, projectId?: string): Promise<{ id: string, slug: string }[]> {
  const res = await db.query<{ id: string, slug: string }>(
    `UPDATE projects SET ai_opt_out = true
      WHERE NOT ai_opt_out AND ($1::uuid IS NULL OR id = $1::uuid)
        AND (profile_id IN (${AI_LOCKED_PROFILES}) OR profile_pr_id IN (${AI_LOCKED_PROFILES})
             OR profile_nightly_id IN (${AI_LOCKED_PROFILES}) OR profile_release_id IN (${AI_LOCKED_PROFILES})
             OR EXISTS (SELECT 1 FROM scans s WHERE s.project_id = projects.id AND s.profile_id IN (${AI_LOCKED_PROFILES})))
      RETURNING id::text, slug`, [projectId ?? null])
  return res.rows
}

/** Le projet est-il sous un verrou « aucun envoi à l'IA » ? (l'interface le montre verrouillé). */
export async function aiOptOutLocked(db: Queryable, projectId: string): Promise<boolean> {
  const res = await db.query(
    `SELECT 1 FROM projects WHERE id = $1
        AND (profile_id IN (${AI_LOCKED_PROFILES}) OR profile_pr_id IN (${AI_LOCKED_PROFILES})
             OR profile_nightly_id IN (${AI_LOCKED_PROFILES}) OR profile_release_id IN (${AI_LOCKED_PROFILES})
             OR EXISTS (SELECT 1 FROM scans s WHERE s.project_id = projects.id AND s.profile_id IN (${AI_LOCKED_PROFILES})))`, [projectId])
  return !!res.rowCount
}
