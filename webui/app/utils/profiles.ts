// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aides des pages Profils (0.7, chantier C) : types renvoyés par l'API,
// message d'erreur profiles.* (avec les verrous refusés), brouillon de verrous.

import type { ProfileLocks } from '#shared/analysis'

export type ProfileLevel = 'enterprise' | 'team' | 'project'
export const PROFILE_LEVELS: ProfileLevel[] = ['enterprise', 'team', 'project']
export const PROFILE_SLOTS = ['default', 'pr', 'nightly', 'release'] as const
export type ProfileSlot = (typeof PROFILE_SLOTS)[number]

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
  rulesets: { ruleset_id: string, slug: string, engine: string, pinned_version: number | null }[]
  archived_at: string | null
  updated_at: string
  updated_by_username: string | null
  projects: number
  children: number
}

export interface ProfilePreview {
  effective: { chain: string[], categories: string[], include_modules: string[], exclude_modules: string[], locks: ProfileLocks }
  modules: { id: string, version: string, categories: string[], reason: string, expected_ms: number | null, measured: 'project' | 'appliance' | null, ram_mb: number, cpu: number }[]
  missing: { category: string | null, module: string | null, reason: string, install: { id: string, name: string }[] }[]
  estimate: { duration_ms: number, unmeasured: string[], peak_ram_mb: number, peak_cpu: number }
  coverage: { detected: boolean, covered: string[], uncovered: string[], unused: string[] } | null
  violations: LockViolation[]
}

export interface LockViolation { field: string, locked: unknown, requested: unknown }

export function emptyLocks(): ProfileLocks {
  return { required_categories: [], required_modules: [], gate_floor: {}, ai_opt_out: false }
}

/** Copie modifiable de verrous reçus de l'API. */
export function cloneLocks(l: ProfileLocks | null | undefined): ProfileLocks {
  const v = l ?? emptyLocks()
  return { required_categories: [...v.required_categories], required_modules: [...v.required_modules], gate_floor: { ...v.gate_floor }, ai_opt_out: v.ai_opt_out }
}

interface ErrLike { data?: { data?: { code?: string, violations?: LockViolation[], profile?: string }, code?: string } }

/** Code d'erreur et détails renvoyés par l'API. */
export function profileErrorDetails(err: unknown): { code?: string, violations: LockViolation[], profile?: string } {
  const d = (err as ErrLike)?.data
  return { code: d?.data?.code ?? d?.code, violations: d?.data?.violations ?? [], profile: d?.data?.profile }
}

/** Libellé d'un champ de verrou (gate_floor.<règle>, exclude_modules, ai_opt_out). */
export function lockFieldLabel(field: string, t: (k: string) => string, te: (k: string) => boolean): string {
  if (field.startsWith('gate_floor.')) {
    const key = field.slice('gate_floor.'.length)
    return te(`gates.fields.${key}`) ? t(`gates.fields.${key}`) : key
  }
  return te(`profiles.lockFields.${field}`) ? t(`profiles.lockFields.${field}`) : field
}

/** Valeur lisible d'un verrou (gravité, nombre, booléen, « jamais bloquant »). */
export function lockValueLabel(v: unknown, t: (k: string) => string, te: (k: string) => boolean): string {
  if (v === null) return t('gates.none')
  if (typeof v === 'boolean') return v ? t('common.yes') : t('common.no')
  if (typeof v === 'string' && te(`gates.severities.${v}`)) return t(`gates.severities.${v}`)
  return String(v)
}

/** Jeu de règles attaché à un profil (G4) : dernière version (null) ou version épinglée. */
export interface RulesetAttachment { ruleset_id: string, pinned_version: number | null }
