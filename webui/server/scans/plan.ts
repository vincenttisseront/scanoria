// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Plan d'une analyse (G7, G11). Un profil exprime des catégories : elles se
// résolvent vers les modules scanners installés, sains et actifs dont les
// catégories et les entrées conviennent à la source. Une catégorie sans module
// devient un trou de couverture. Le plan figé (scans.plan) garde tout ce qu'il
// faut pour rejouer l'analyse à l'identique : modules, versions, empreintes,
// options, bases, règles du quality gate et commit.

import { readFile } from 'node:fs/promises'
import { z } from 'zod'
import { CATEGORIES, GateRules, ProfileLocks, type Category } from '#shared/analysis'
import { MODULE_ID_RE } from '#shared/schemas'
import { resolveOptions } from '#shared/module-options'
import type { InstalledModule } from '../utils/catalog'
import { applyPins, retainedAvailable, type ModulePin, type RetainedImage } from '../vigilance/pins'

export const PLAN_VERSION = 1
/** Catégorie des modules système (chantier B) : hors des profils. */
export const SYSTEM_CATEGORY = 'system'

/** Ce que le plan retient du manifeste d'un scanner (champ scan de l'index). */
const scanSpecSchema = z.object({
  inputs: z.array(z.string()).max(8).default([]),
  timeout_s: z.number().int().min(1).max(86_400).default(900),
  history: z.enum(['shallow', 'full']).optional(),
  /**
   * Module d'appoint (0.5, reach-index pour I11) : lancé seulement quand un
   * autre module du plan couvre cette catégorie, jamais compté dans la
   * couverture (G15) ni bloquant pour le verdict (G13).
   */
  companion: z.enum(CATEGORIES).optional(),
  /** 0.5 (contrat 14) et 0.6 (V3) : le module lit le SBOM de l'analyse ; graphe du plan (order.ts). */
  prefers_sbom: z.boolean().optional(),
  requires_sbom: z.boolean().optional(),
})
export type ScanSpec = z.infer<typeof scanSpecSchema>

/** Entrée de l'index utile au plan : type, catégories, image, sorties, bases, scan, options. */
export interface PlanCatalogEntry {
  id: string
  version: string
  type: string
  categories: string[]
  image: string | null
  restrictions: string
  feeds: string[]
  outputs: string[]
  options: unknown
  scan: ScanSpec | null
}

export type PlanInput = 'repo' | 'archive'

export interface PlannedFeed { id: string, version: string | null }

export interface PlannedModule {
  id: string
  version: string
  image: string | null
  image_digest: string | null
  categories: string[]
  options: Record<string, unknown>
  feeds: PlannedFeed[]
  timeout_s: number
  history: 'shallow' | 'full'
  outputs: string[]
  /** Pourquoi le module est dans le plan (affiché dans la console) ; « companion » : module d'appoint. */
  reason: 'category' | 'included' | 'companion'
  /** 0.6 (B, contrats 24 et 25) : version figée par le projet (G6) ou candidate d'un essai (F13). */
  alternate?: 'pin' | 'trial'
  /** 0.6 (V3) : modules du plan à terminer avant celui-ci (order.ts). Absent d'un plan antérieur. */
  after?: string[]
  /** 0.6 (V5) : durée attendue (ms) qui a fixé la place du module dans le plan. */
  expected_ms?: number
}

export interface CoverageGap {
  /** Origine du trou (le chantier D ajoute les siens avec d'autres kind). */
  kind: 'profile-category' | 'profile-module'
  /** Catégorie du profil sans module, ou module demandé indisponible. */
  category: string | null
  module: string | null
  reason: 'no-module' | 'not-installed' | 'unhealthy' | 'disabled' | 'input' | 'license'
}

export interface ScanPlan {
  version: typeof PLAN_VERSION
  created_at: string
  /** « sbom » (0.5) : re-corrélation d'un SBOM déjà relevé (contrat 16). */
  source: {
    kind: 'git' | 'archive' | 'sbom'
    ref: string
    commit: string | null
    history: 'shallow' | 'full'
    /** 0.7 (D, contrat 33) : analyse incrémentale d'une PR, fichiers modifiés figés (G11, G18). */
    changed_files?: string[]
  }
  profile: { id: string, slug: string, categories: string[], include_modules: string[], exclude_modules: string[] } & Partial<Pick<import('../profiles/plan-profile').PlanProfile, 'level' | 'chain' | 'locks' | 'slot' | 'source'>>
  gate: { id: string, slug: string, rules: GateRules }
  modules: PlannedModule[]
  gaps: CoverageGap[]
  /** Somme des délais des modules (le runner les enchaîne). */
  timeout_s: number
}

export interface ProfileInput {
  id: string
  slug: string
  categories: string[]
  include_modules: string[]
  exclude_modules: string[]
}

const digestOf = (image: string | null) => (image && /@(sha256:[0-9a-f]{64})$/.exec(image)?.[1]) || null

/** Lit l'index vérifié : la console n'en garde pas le champ scan, le plan en a besoin. */
export async function readPlanCatalog(path: string): Promise<Map<string, PlanCatalogEntry>> {
  const out = new Map<string, PlanCatalogEntry>()
  let raw: unknown
  try {
    const buf = await readFile(path)
    if (buf.length > 8 * 1024 * 1024) return out
    raw = JSON.parse(buf.toString('utf8'))
  }
  catch {
    return out
  }
  const modules = (raw as { modules?: unknown })?.modules
  for (const m of Array.isArray(modules) ? modules.slice(0, 1000) : []) {
    const entry = catalogEntry(m)
    if (entry) out.set(`${entry.id}@${entry.version}`, entry)
  }
  return out
}

const strList = (v: unknown, max = 64) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').slice(0, max) : [])

export function catalogEntry(m: unknown): PlanCatalogEntry | null {
  if (!m || typeof m !== 'object') return null
  const o = m as Record<string, unknown>
  if (typeof o.id !== 'string' || !MODULE_ID_RE.test(o.id) || typeof o.version !== 'string' || typeof o.type !== 'string') return null
  const scan = o.scan === undefined || o.scan === null ? null : scanSpecSchema.safeParse(o.scan)
  if (scan && !scan.success) return null
  const req = (o.requires ?? {}) as Record<string, unknown>
  const needs = (o.needs ?? {}) as Record<string, unknown>
  const license = (o.license ?? {}) as Record<string, unknown>
  return {
    id: o.id,
    version: o.version,
    type: o.type,
    categories: strList(o.categories, 20),
    image: typeof o.image === 'string' ? o.image : null,
    restrictions: typeof license.restrictions === 'string' ? license.restrictions : 'none',
    feeds: [...new Set([...strList(req.feeds), ...strList(needs.feeds)])],
    outputs: o.outputs && typeof o.outputs === 'object' ? Object.keys(o.outputs as object).filter(k => k === 'sarif' || k === 'cyclonedx') : [],
    options: o.options ?? null,
    scan: scan ? scan.data : null,
  }
}

export interface ResolveInput {
  profile: ProfileInput
  /** « sbom » (0.5) : re-corrélation, modules qui lisent l'entrée « sbom ». */
  sourceKind: 'git' | 'archive' | 'sbom'
  /** Licence OSI déclarée du projet : seule une source open source admet un module « private-code-forbidden ». */
  projectLicense: string | null
  installed: InstalledModule[]
  catalog: Map<string, PlanCatalogEntry>
  /**
   * Délais forcés par module (« scan.timeout_overrides », appliqués par une
   * personne depuis un diagnostic I15) : ne font qu'allonger le délai du manifeste.
   */
  timeoutOverrides?: Record<string, number>
  /** 0.6 (B, contrat 24) : versions figées du projet, par module. */
  pins?: Map<string, ModulePin>
}

/**
 * Résolution du profil (G7) : catégories + include_modules − exclude_modules,
 * vers les scanners installés, sains, actifs, compatibles avec la source.
 */
export function resolveProfile(input: ResolveInput): { modules: PlannedModule[], gaps: CoverageGap[] } {
  const { profile } = input
  const want: PlanInput | 'sbom' = input.sourceKind === 'git' ? 'repo' : input.sourceKind === 'sbom' ? 'sbom' : 'archive'
  const exclude = new Set(profile.exclude_modules)
  const include = new Set(profile.include_modules.filter(id => !exclude.has(id)))
  const categories = new Set(profile.categories.filter(c => (CATEGORIES as readonly string[]).includes(c)))
  const feedsById = new Map(input.installed.filter(m => m.type === 'feed').map(m => [m.id, m]))
  const modules: PlannedModule[] = []
  const gaps: CoverageGap[] = []
  const covered = new Set<string>()

  const usable = (m: InstalledModule): CoverageGap['reason'] | null => {
    if (m.status !== 'healthy') return m.status === 'disabled' ? 'disabled' : 'unhealthy'
    if (!m.enabled) return 'disabled'
    return null
  }

  const companions: InstalledModule[] = []
  for (const m of [...input.installed].sort((a, b) => a.id.localeCompare(b.id))) {
    if (m.type !== 'scanner' || exclude.has(m.id)) continue
    const entry = input.catalog.get(`${m.id}@${m.version}`)
    // Modules système (git-fetch, catégorie « system ») : utilisés par le runner, jamais planifiés.
    if (entry?.categories.includes(SYSTEM_CATEGORY)) continue
    const explicit = include.has(m.id)
    if (entry?.scan?.companion && !explicit) {
      companions.push(m)
      continue
    }
    const matching = entry ? entry.categories.filter(c => categories.has(c)) : []
    if (!explicit && matching.length === 0) continue
    const problem = usable(m)
      ?? (!entry || !entry.scan ? 'not-installed' : null)
      ?? (!entry!.scan!.inputs.includes(want) ? 'input' : null)
      ?? (entry!.restrictions === 'private-code-forbidden' && !input.projectLicense ? 'license' : null)
    if (problem) {
      if (explicit) gaps.push({ kind: 'profile-module', category: null, module: m.id, reason: problem })
      continue
    }
    const e = entry!
    const options = resolveOptions(e.options, m.options).values
    const history = e.scan!.history === 'full' && options.history !== false ? 'full' : 'shallow'
    modules.push({
      id: m.id,
      version: m.version,
      image: e.image,
      image_digest: digestOf(e.image),
      categories: e.categories,
      options,
      feeds: e.feeds.map(id => ({ id, version: feedsById.get(id)?.version ?? null })),
      timeout_s: Math.min(86_400, Math.max(e.scan!.timeout_s, input.timeoutOverrides?.[m.id] ?? 0)),
      history,
      outputs: e.outputs,
      reason: matching.length ? 'category' : 'included',
    })
    for (const c of matching) covered.add(c)
  }
  // Modules d'appoint : seulement si un module planifié couvre leur catégorie ; un appoint
  // indisponible est simplement omis (ce n'est pas un trou de couverture).
  for (const m of companions) {
    const e = input.catalog.get(`${m.id}@${m.version}`)!
    if (!modules.some(x => x.categories.includes(e.scan!.companion!))) continue
    if (usable(m) || !e.scan!.inputs.includes(want) || (e.restrictions === 'private-code-forbidden' && !input.projectLicense)) continue
    modules.push({
      id: m.id,
      version: m.version,
      image: e.image,
      image_digest: digestOf(e.image),
      categories: e.categories,
      options: resolveOptions(e.options, m.options).values,
      feeds: e.feeds.map(id => ({ id, version: feedsById.get(id)?.version ?? null })),
      timeout_s: Math.min(86_400, Math.max(e.scan!.timeout_s, input.timeoutOverrides?.[m.id] ?? 0)),
      history: 'shallow',
      outputs: e.outputs,
      reason: 'companion',
    })
  }
  for (const id of include) {
    if (!modules.some(m => m.id === id) && !gaps.some(g => g.module === id)) {
      gaps.push({ kind: 'profile-module', category: null, module: id, reason: 'not-installed' })
    }
  }
  for (const c of profile.categories) {
    if (!covered.has(c)) gaps.push({ kind: 'profile-category', category: c as Category, module: null, reason: 'no-module' })
  }
  return { modules: input.pins ? applyPins(modules, input.pins) : modules, gaps }
}

export function planTimeout(modules: PlannedModule[]): number {
  return modules.reduce((sum, m) => sum + m.timeout_s, 0)
}

/** Source d'un plan : historique complet si un module le demande (gitleaks). */
export function planHistory(modules: PlannedModule[]): 'shallow' | 'full' {
  return modules.some(m => m.history === 'full') ? 'full' : 'shallow'
}

/**
 * Rejeu (G11) : les modules du plan d'origine qui ne sont plus installés,
 * sains et actifs à la même version sont constatés manquants.
 */
export function replayAvailability(plan: ScanPlan, installed: InstalledModule[], retained?: RetainedImage[] | null): { available: PlannedModule[], missing: PlannedModule[] } {
  const byId = new Map(installed.map(m => [m.id, m]))
  const available: PlannedModule[] = []
  const missing: PlannedModule[] = []
  for (const m of plan.modules) {
    const cur = byId.get(m.id)
    const usable = !!cur && cur.status === 'healthy' && cur.enabled
    // 0.6 (B) : version figée ou candidate, présente si le helper la retient (contrats 24, 25).
    if (usable && (cur.version === m.version || (m.alternate && retainedAvailable(m, retained)))) available.push(m)
    else missing.push(m)
  }
  return { available, missing }
}

const plannedModuleSchema = z.object({
  id: z.string().regex(MODULE_ID_RE),
  version: z.string().min(1).max(64),
  image: z.string().nullable(),
  image_digest: z.string().nullable(),
  categories: z.array(z.string()),
  options: z.record(z.string(), z.unknown()),
  feeds: z.array(z.object({ id: z.string(), version: z.string().nullable() })),
  timeout_s: z.number().int().min(1),
  history: z.enum(['shallow', 'full']),
  outputs: z.array(z.string()),
  reason: z.enum(['category', 'included', 'companion']),
  alternate: z.enum(['pin', 'trial']).optional(),
  after: z.array(z.string().regex(MODULE_ID_RE)).max(64).optional(),
  expected_ms: z.number().int().min(0).optional(),
})

export const scanPlanSchema = z.object({
  version: z.literal(PLAN_VERSION),
  created_at: z.string(),
  source: z.object({
    kind: z.enum(['git', 'archive', 'sbom']),
    ref: z.string(),
    commit: z.string().nullable(),
    history: z.enum(['shallow', 'full']),
    changed_files: z.array(z.string().min(1).max(1024)).max(3000).optional(),
  }),
  profile: z.object({
    id: z.string(), slug: z.string(), categories: z.array(z.string()),
    include_modules: z.array(z.string()), exclude_modules: z.array(z.string()),
    // 0.7 (C, G8, G9, contrat 29) : profil effectif figé ; absents d'un plan plus ancien.
    level: z.enum(['enterprise', 'team', 'project']).optional(),
    chain: z.array(z.string()).max(3).optional(),
    locks: ProfileLocks.optional(),
    slot: z.enum(['pr', 'nightly', 'release', 'default']).optional(),
    source: z.enum(['project', 'explicit', 'config']).optional(),
  }),
  gate: z.object({ id: z.string(), slug: z.string(), rules: GateRules }),
  modules: z.array(plannedModuleSchema).max(64),
  gaps: z.array(z.object({
    kind: z.enum(['profile-category', 'profile-module']),
    category: z.string().nullable(),
    module: z.string().nullable(),
    reason: z.enum(['no-module', 'not-installed', 'unhealthy', 'disabled', 'input', 'license']),
  })),
  timeout_s: z.number().int().min(0),
})

/** Relit un plan enregistré ; null s'il est absent ou mal formé. */
export function parsePlan(value: unknown): ScanPlan | null {
  const parsed = scanPlanSchema.safeParse(value)
  return parsed.success ? parsed.data as ScanPlan : null
}

/**
 * 0.7 (D, contrat 33) : fichiers modifiés d'une analyse incrémentale de PR,
 * figés dans le plan (G11). Absents, trop nombreux ou analyse non
 * incrémentale : rien (analyse complète).
 */
export function incrementalFiles(scan: { incremental?: boolean | null, pull_request?: unknown }): string[] | undefined {
  if (!scan.incremental) return undefined
  const files = (scan.pull_request as { changed_files?: unknown } | null)?.changed_files
  if (!Array.isArray(files) || files.length > 3000) return undefined
  const ok = files.filter((f): f is string => typeof f === 'string' && f.length > 0 && f.length <= 1024
    && !f.startsWith('/') && !f.split('/').some(s => s === '' || s === '.' || s === '..')
    // eslint-disable-next-line no-control-regex
    && !/[\u0000-\u001F\u007F]/.test(f))
  return ok.length === files.length ? ok : undefined
}
