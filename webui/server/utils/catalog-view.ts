// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Vue du catalogue servie à la console : index + état des modules + machine,
// avec la compatibilité de chaque module et de chaque pack, le graphe des
// dépendances (G1) et la sélection conseillée (§ 5.3).

import { getConfig } from './config'
import { getRunningVersion, readPublishedState } from './appliance'
import {
  RECOMMENDED_IDS, compareVersions, latestModules, readCatalogIndex, readDnsStatus, readModulesState,
  type CatalogIndex, type CatalogModule, type InstalledModule,
} from './catalog'
import { buildInstallPlan, dependentsOf, type InstallPlan, type Machine, type PlanContext } from './module-plan'

export interface CatalogContext extends PlanContext {
  index: CatalogIndex | null
  operations: Awaited<ReturnType<typeof readModulesState>>['operations']
  feeds: Awaited<ReturnType<typeof readModulesState>>['feeds']
  stateAvailable: boolean
}

function machineFrom(state: Record<string, unknown> | null): Machine | null {
  const a = state?.appliance as { cpu_count?: unknown, memory_mb?: unknown } | undefined
  const disks = Array.isArray(state?.disks) ? state.disks : []
  if (typeof a?.cpu_count !== 'number' || typeof a?.memory_mb !== 'number') return null
  return {
    cpu_count: a.cpu_count,
    memory_mb: a.memory_mb,
    disks: disks.filter((d): d is Machine['disks'][number] =>
      !!d && typeof d.mount === 'string' && typeof d.avail_mb === 'number' && typeof d.size_mb === 'number'),
  }
}

export async function loadCatalogContext(): Promise<CatalogContext> {
  const cfg = getConfig()
  const [index, modules, dns, published, version] = await Promise.all([
    readCatalogIndex(cfg.catalogIndexFile),
    readModulesState(cfg.modulesStateFile),
    readDnsStatus(cfg.dnsStatusFile),
    readPublishedState(cfg.stateFile),
    getRunningVersion(cfg.versionFile),
  ])
  return {
    index,
    installed: modules.modules,
    operations: modules.operations,
    feeds: modules.feeds,
    stateAvailable: modules.available,
    machine: published.state ? machineFrom(published.state) : null,
    applianceVersion: version,
    dns,
  }
}

/** Manifeste réduit à ce que la console affiche (jamais l'image ni les unités). */
export function moduleSummary(m: CatalogModule) {
  return {
    id: m.id,
    name: m.name,
    type: m.type,
    version: m.version,
    description: m.description ?? null,
    categories: m.categories,
    license: m.license,
    upstream: m.upstream ?? null,
    resources: m.resources,
    hostname: m.type === 'service' ? m.hostname ?? null : null,
    requires: { modules: m.requires?.modules ?? [], feeds: [...new Set([...(m.requires?.feeds ?? []), ...(m.needs?.feeds ?? [])])], appliance: m.requires?.appliance ?? null },
    conflicts: m.conflicts,
    sysctl: m.needs?.sysctl ?? {},
    postgres: m.needs?.postgres ?? false,
    has_testbed: !!m.testbed,
  }
}

/** Plan d'un seul module, licences réputées acceptées : sert à juger la compatibilité. */
export function compatibility(ctx: CatalogContext, ids: string[]): InstallPlan {
  return buildInstallPlan(ids.map(id => ({ id })), { ...ctx, acceptLicenses: (ctx.index?.modules ?? []).map(m => m.id) })
}

const majorMinor = (v: unknown) => typeof v === 'string' ? v.split('.').slice(0, 2).join('.') : null

/**
 * Variante devenue compatible à la même version (ex. plugin de branches publié
 * après SonarQube) pour une fonction voulue mais inactive : elle s'applique
 * comme une mise à jour, sauvegarde comprise (helper, update-module).
 */
export function variantPending(installed: InstalledModule | undefined, latest: CatalogModule | undefined): boolean {
  if (!installed || !latest || latest.version !== installed.version) return false
  const variants = latest.service?.variants
  if (!Array.isArray(variants)) return false
  return Object.entries(installed.features ?? {}).some(([feature, st]) => !st.active && st.code !== 'disabled'
    && variants.some((v: unknown) => {
      if (!v || typeof v !== 'object') return false
      const x = v as Record<string, unknown>
      return x.feature === feature && x.base_version === latest.version && majorMinor(x.version) === majorMinor(latest.version)
    }))
}

export function updateAvailable(installed: InstalledModule | undefined, latest: CatalogModule | undefined): string | null {
  if (!installed || !latest) return null
  if (variantPending(installed, latest)) return latest.version
  return compareVersions(latest.version, installed.version) > 0 ? latest.version : null
}

export function dependencyEdges(index: CatalogIndex | null) {
  const edges: { from: string, to: string, kind: 'module' | 'feed' | 'conflict' }[] = []
  for (const m of latestModules(index).values()) {
    for (const to of m.requires?.modules ?? []) edges.push({ from: m.id, to, kind: 'module' })
    for (const to of new Set([...(m.requires?.feeds ?? []), ...(m.needs?.feeds ?? [])])) edges.push({ from: m.id, to, kind: 'feed' })
    for (const to of m.conflicts) edges.push({ from: m.id, to, kind: 'conflict' })
  }
  return edges
}

export function buildCatalogView(ctx: CatalogContext) {
  const latest = latestModules(ctx.index)
  const installedById = new Map(ctx.installed.map(i => [i.id, i]))
  const modules = [...latest.values()]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((m) => {
      const installed = installedById.get(m.id)
      const plan = installed ? null : compatibility(ctx, [m.id])
      return {
        ...moduleSummary(m),
        installed: installed ?? null,
        update_available: updateAvailable(installed, m),
        compatible: plan ? plan.blockers.length === 0 : true,
        blockers: plan?.blockers ?? [],
        auto_added: plan?.items.filter(i => i.reason !== 'requested').map(i => i.id) ?? [],
        dependents: installed ? dependentsOf(m.id, ctx) : [],
        feed: installed ? (ctx.feeds ?? []).find(f => f.id === m.id) ?? null : null,
      }
    })
  const orphans = ctx.installed.filter(i => !latest.has(i.id))
  const packs = (ctx.index?.packs ?? []).map((p) => {
    const missing = p.modules.filter(id => !latest.has(id))
    const pending = p.modules.filter(id => latest.has(id) && !installedById.has(id))
    const plan = pending.length ? compatibility(ctx, pending) : null
    return {
      ...p,
      unknown_modules: missing,
      installed_modules: p.modules.filter(id => installedById.has(id)),
      pending_modules: pending,
      plan,
    }
  })
  const recommendedIds = RECOMMENDED_IDS.filter(id => latest.has(id) && !installedById.has(id))
  return {
    index: ctx.index
      ? { available: true, version: ctx.index.version, generated_at: ctx.index.generated_at, rejected: ctx.index.rejected }
      : { available: false, version: null, generated_at: null, rejected: 0 },
    state_available: ctx.stateAvailable,
    machine: ctx.machine,
    appliance_version: ctx.applianceVersion,
    modules,
    orphans,
    packs,
    graph: dependencyEdges(ctx.index),
    recommended: {
      ids: recommendedIds,
      first_access: ctx.installed.length === 0,
      plan: recommendedIds.length ? compatibility(ctx, recommendedIds) : null,
    },
    operations: ctx.operations,
    dns: ctx.dns,
  }
}
