// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Aperçu d'un profil avant enregistrement (G10) : modules résolus (G7 et
// verrous hérités), modules manquants à installer (lien vers le catalogue),
// durée et ressources estimées (mesures F14 et V5), couverture obtenue sur un
// dépôt choisi (détection F1). Lecture seule, sans effet.

import { z } from 'zod'
import { CATEGORIES, ProfileLocks } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import type { Queryable } from '../utils/db'
import { latestModules, type CatalogIndex, type InstalledModule } from '../utils/catalog'
import { resolveProfile as resolvePlanModules, type PlanCatalogEntry } from '../scans/plan'
import { loadDurations } from '../scans/order'
import { mergeChain, type EffectiveProfile } from './resolve'
import { EMPTY_LOCKS, findLoosening, mergeAll } from './locks'
import { ProfileError, profileChain } from './service'

const moduleId = z.string().regex(MODULE_ID_RE)

export const profilePreviewSchema = z.strictObject({
  /** Profil existant (modifié) : sa chaîne et ses enfants sont pris en compte. */
  profile_id: z.string().uuid().nullable().default(null),
  parent_id: z.string().uuid().nullable().default(null),
  slug: z.string().max(63).default('apercu'),
  categories: z.array(z.enum(CATEGORIES)).max(32).default([]),
  include_modules: z.array(moduleId).max(64).default([]),
  exclude_modules: z.array(moduleId).max(64).default([]),
  locks: ProfileLocks.default(EMPTY_LOCKS),
  /** Dépôt de référence pour la couverture (détection F1). */
  project_id: z.string().uuid().nullable().default(null),
})
export type ProfilePreviewInput = z.infer<typeof profilePreviewSchema>

export interface PreviewModule {
  id: string
  version: string
  categories: string[]
  reason: 'category' | 'included' | 'companion'
  /** Durée moyenne mesurée (ms) : ce projet d'abord, sinon l'appliance ; null sans mesure. */
  expected_ms: number | null
  measured: 'project' | 'appliance' | null
  ram_mb: number
  cpu: number
}

export interface ProfilePreview {
  effective: Pick<EffectiveProfile, 'categories' | 'include_modules' | 'exclude_modules' | 'locks'> & { chain: string[] }
  modules: PreviewModule[]
  /** Catégories ou modules demandés qu'aucun module installé ne couvre, avec ce que le catalogue propose. */
  missing: { category: string | null, module: string | null, reason: string, install: { id: string, name: string }[] }[]
  estimate: {
    /** Somme des durées mesurées (le runner enchaîne les modules d'une analyse). */
    duration_ms: number
    /** Modules sans mesure (durée inconnue, comptée à part). */
    unmeasured: string[]
    /** Pic de mémoire : le plus gros module (un conteneur à la fois). */
    peak_ram_mb: number
    peak_cpu: number
  }
  coverage: null | {
    project_id: string
    detected: boolean
    /** Catégories utiles au dépôt (F1) couvertes par le profil. */
    covered: string[]
    /** Catégories utiles au dépôt que le profil ne couvre pas (trou de couverture). */
    uncovered: string[]
    /** Catégories du profil sans objet pour ce dépôt. */
    unused: string[]
  }
  /** Verrous hérités que le brouillon assouplirait (refusé à l'enregistrement). */
  violations: ReturnType<typeof findLoosening>
}

export interface PreviewContext {
  installed: InstalledModule[]
  catalog: Map<string, PlanCatalogEntry>
  index: CatalogIndex | null
}

export async function previewProfile(db: Queryable, input: ProfilePreviewInput, ctx: PreviewContext): Promise<ProfilePreview> {
  const parentChain = input.parent_id ? await profileChain(db, input.parent_id) : []
  if (!parentChain) throw new ProfileError('E_PROFILE_PARENT', 404)
  const chainRows = parentChain.map(c => ({ id: c.id, slug: c.slug, level: c.level, parent_id: null, categories: [] as string[], include_modules: [] as string[], exclude_modules: [] as string[], locks: c.locks, rulesets: [] }))
  // Contenu (catégories, modules) des ancêtres, lu en base.
  if (chainRows.length) {
    const r = await db.query<{ id: string, categories: string[], include_modules: string[], exclude_modules: string[] }>(
      'SELECT id::text, categories, include_modules, exclude_modules FROM profiles WHERE id = ANY($1::uuid[])', [chainRows.map(c => c.id)])
    for (const row of r.rows) Object.assign(chainRows.find(c => c.id === row.id)!, row)
  }
  const inherited = mergeAll(parentChain.map(c => c.locks))
  const draft = {
    id: input.profile_id ?? '00000000-0000-4000-8000-000000000000', slug: input.slug, level: 'project' as const, parent_id: null,
    categories: input.categories, include_modules: input.include_modules, exclude_modules: input.exclude_modules,
    locks: input.locks, rulesets: [],
  }
  const effective = mergeChain([...chainRows, draft])
  const violations = findLoosening(inherited, { locks: input.locks, exclude_modules: input.exclude_modules })

  let sourceKind: 'git' | 'archive' = 'git'
  let projectLicense: string | null = null
  let detection: { categories?: unknown } | null = null
  if (input.project_id) {
    const p = await db.query<{ source_kind: 'git' | 'archive', spdx_license: string | null, detection: { categories?: unknown } | null }>(
      'SELECT source_kind, spdx_license, detection FROM projects WHERE id = $1', [input.project_id])
    if (p.rows[0]) ({ source_kind: sourceKind, spdx_license: projectLicense, detection } = p.rows[0])
  }
  const resolved = resolvePlanModules({
    profile: { id: draft.id, slug: draft.slug, categories: effective.categories, include_modules: effective.include_modules, exclude_modules: effective.exclude_modules },
    sourceKind, projectLicense, installed: ctx.installed, catalog: ctx.catalog,
  })

  const latest = latestModules(ctx.index)
  const durations = await loadDurations(db, input.project_id ?? '00000000-0000-4000-8000-000000000000', resolved.modules.map(m => m.id))
  const modules: PreviewModule[] = resolved.modules.map((m) => {
    const own = durations.project.get(m.id)
    const all = durations.appliance.get(m.id)
    const res = latest.get(m.id)?.resources
    return {
      id: m.id, version: m.version, categories: m.categories, reason: m.reason,
      expected_ms: own ?? all ?? null, measured: own !== undefined ? 'project' : all !== undefined ? 'appliance' : null,
      ram_mb: res?.min_ram_mb ?? 0, cpu: res?.min_cpu ?? 0,
    }
  })
  const scanners = [...latest.values()].filter(m => m.type === 'scanner' && !m.categories.includes('system'))
  const missing = resolved.gaps.map(g => ({
    category: g.category, module: g.module, reason: g.reason,
    install: (g.category
      ? scanners.filter(m => m.categories.includes(g.category!))
      : scanners.filter(m => m.id === g.module))
      .filter(m => !ctx.installed.some(i => i.id === m.id && i.status === 'healthy' && i.enabled))
      .slice(0, 8).map(m => ({ id: m.id, name: m.name })),
  }))

  let coverage: ProfilePreview['coverage'] = null
  if (input.project_id) {
    const wanted = Array.isArray(detection?.categories) ? (detection!.categories as unknown[]).filter((c): c is string => typeof c === 'string') : null
    const got = new Set(resolved.modules.flatMap(m => m.categories))
    coverage = wanted
      ? {
          project_id: input.project_id, detected: true,
          covered: wanted.filter(c => got.has(c)).sort(),
          uncovered: wanted.filter(c => !got.has(c)).sort(),
          unused: effective.categories.filter(c => !wanted.includes(c)).sort(),
        }
      : { project_id: input.project_id, detected: false, covered: [], uncovered: [], unused: [] }
  }

  return {
    effective: {
      categories: effective.categories, include_modules: effective.include_modules, exclude_modules: effective.exclude_modules,
      locks: effective.locks, chain: [...parentChain.map(c => c.slug), input.slug],
    },
    modules,
    missing,
    estimate: {
      duration_ms: modules.reduce((s, m) => s + (m.expected_ms ?? 0), 0),
      unmeasured: modules.filter(m => m.expected_ms === null).map(m => m.id),
      peak_ram_mb: Math.max(0, ...modules.map(m => m.ram_mb)),
      peak_cpu: Math.max(0, ...modules.map(m => m.cpu)),
    },
    coverage,
    violations,
  }
}
