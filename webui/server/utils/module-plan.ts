// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Plan d'installation calculé par la console avant toute demande (G1, F11, § 4.3) :
// - dépendances (requires.modules, requires.feeds, needs.feeds) ajoutées
//   automatiquement, avec la raison (principe 8) ;
// - conflits, version minimale de l'appliance, licences à accepter ;
// - contrôle global des ressources (RAM, CPU, disque) ;
// - options complétées par les défauts et validées (G3).
// Le helper refait tous ces contrôles : ce plan sert à expliquer et à refuser tôt.

import { resolveOptions, changedOptions, type OptionIssue } from '#shared/module-options'
import {
  findModule, latestModules, satisfiesAppliance,
  type CatalogIndex, type CatalogModule, type DnsStatus, type InstalledModule,
} from './catalog'

/** Mémoire laissée à la console et au système (plancher D6 : 4 Go au total). */
export const RESERVED_RAM_MB = 2048
const CONTAINERS_DIR = '/var/lib/containers'

export interface Machine {
  cpu_count: number
  memory_mb: number
  disks: { mount: string, size_mb: number, avail_mb: number }[]
}

export interface PlanRequest {
  id: string
  version?: string
  options?: Record<string, unknown>
}

export type PlanReason = 'requested' | 'dependency' | 'feed'

export interface PlanItem {
  id: string
  name: string
  version: string
  type: CatalogModule['type']
  reason: PlanReason
  required_by: string[]
  license: CatalogModule['license']
  needs_acceptance: boolean
  options: Record<string, unknown>
  changed_options: string[]
  resources: CatalogModule['resources']
  hostname: string | null
}

export interface PlanIssue {
  code: 'E_NOT_FOUND' | 'E_DEPENDENCY' | 'E_CONFLICT' | 'E_APPLIANCE_VERSION' | 'E_LICENSE_REQUIRED'
    | 'E_RESOURCES' | 'E_OPTIONS' | 'E_DUPLICATE' | 'E_HOSTNAME' | 'W_RESOURCES_UNKNOWN' | 'W_DNS' | 'W_DNS_UNKNOWN'
    | 'W_INSTALLED' | 'W_PACK_INSTALLED'
  module?: string
  other?: string
  options?: OptionIssue[]
}

export interface ResourceCheck {
  kind: 'ram' | 'cpu' | 'disk'
  needed: number
  available: number | null
  ok: boolean
}

export interface InstallPlan {
  ok: boolean
  items: PlanItem[]
  skipped: string[]
  checks: ResourceCheck[]
  blockers: PlanIssue[]
  warnings: PlanIssue[]
  licenses_to_accept: string[]
  sysctl: { module: string, key: string, value: string | number }[]
}

const PERMANENT = new Set(['service', 'runner'])

function dependencyIds(m: CatalogModule): { id: string, reason: PlanReason }[] {
  const out: { id: string, reason: PlanReason }[] = []
  for (const id of m.requires?.modules ?? []) out.push({ id, reason: 'dependency' })
  for (const id of [...(m.requires?.feeds ?? []), ...(m.needs?.feeds ?? [])]) out.push({ id, reason: 'feed' })
  return out
}

/** Disque qui porte le stockage des conteneurs (point de montage le plus long qui le contient). */
export function containersDisk(disks: Machine['disks']): Machine['disks'][number] | undefined {
  return disks
    .filter(d => CONTAINERS_DIR === d.mount || CONTAINERS_DIR.startsWith(d.mount.endsWith('/') ? d.mount : `${d.mount}/`))
    .sort((a, b) => b.mount.length - a.mount.length)[0]
}

export function resourceChecks(
  newModules: Pick<CatalogModule, 'type' | 'resources'>[],
  installed: { module: Pick<CatalogModule, 'type' | 'resources'>, enabled: boolean }[],
  machine: Machine | null,
): ResourceCheck[] {
  const permanent = [...installed.filter(i => i.enabled).map(i => i.module), ...newModules].filter(m => PERMANENT.has(m.type))
  const transient = [...installed.map(i => i.module), ...newModules].filter(m => !PERMANENT.has(m.type))
  const ram = RESERVED_RAM_MB
    + permanent.reduce((s, m) => s + m.resources.min_ram_mb, 0)
    + Math.max(0, ...transient.map(m => m.resources.min_ram_mb))
  const cpu = Math.max(0, ...[...newModules, ...installed.filter(i => i.enabled).map(i => i.module)].map(m => m.resources.min_cpu))
  const disk = newModules.reduce((s, m) => s + m.resources.disk_mb, 0)
  const avail = machine ? containersDisk(machine.disks)?.avail_mb ?? null : null
  return [
    { kind: 'ram', needed: ram, available: machine?.memory_mb ?? null, ok: !machine || ram <= machine.memory_mb },
    { kind: 'cpu', needed: cpu, available: machine?.cpu_count ?? null, ok: !machine || cpu <= machine.cpu_count },
    { kind: 'disk', needed: disk, available: avail, ok: avail === null || disk <= avail },
  ]
}

export interface PlanContext {
  index: CatalogIndex | null
  installed: InstalledModule[]
  machine: Machine | null
  applianceVersion: string
  dns: DnsStatus | null
  acceptLicenses?: string[]
}

export function buildInstallPlan(requests: PlanRequest[], ctx: PlanContext): InstallPlan {
  const blockers: PlanIssue[] = []
  const warnings: PlanIssue[] = []
  const installedIds = new Set(ctx.installed.map(m => m.id))
  const items = new Map<string, PlanItem>()
  const skipped: string[] = []
  const accepted = new Set(ctx.acceptLicenses ?? [])

  const seen = new Set<string>()
  for (const r of requests) {
    if (seen.has(r.id)) blockers.push({ code: 'E_DUPLICATE', module: r.id })
    seen.add(r.id)
  }

  const add = (id: string, reason: PlanReason, by: string | null, req?: PlanRequest, recurse = true) => {
    const existing = items.get(id)
    if (existing) {
      if (by && !existing.required_by.includes(by)) existing.required_by.push(by)
      return
    }
    if (installedIds.has(id)) {
      if (reason === 'requested') warnings.push({ code: 'W_INSTALLED', module: id })
      if (!skipped.includes(id)) skipped.push(id)
      return
    }
    const m = findModule(ctx.index, id, req?.version)
    if (!m) {
      blockers.push(by ? { code: 'E_DEPENDENCY', module: by, other: id } : { code: 'E_NOT_FOUND', module: id })
      return
    }
    const opts = resolveOptions(m.options, req?.options ?? {})
    if (opts.issues.length) blockers.push({ code: 'E_OPTIONS', module: id, options: opts.issues })
    const needsAcceptance = m.license.restrictions !== 'none'
    items.set(id, {
      id,
      name: m.name,
      version: m.version,
      type: m.type,
      reason,
      required_by: by ? [by] : [],
      license: m.license,
      needs_acceptance: needsAcceptance,
      options: opts.values,
      changed_options: changedOptions(m.options, opts.values),
      resources: m.resources,
      hostname: m.type === 'service' ? m.hostname ?? null : null,
    })
    if (recurse) for (const dep of dependencyIds(m)) add(dep.id, dep.reason, id)
  }
  // Demandes explicites d'abord (leurs options et leur version priment), puis leurs dépendances.
  for (const r of requests) add(r.id, 'requested', null, r, false)
  for (const r of requests) {
    const m = items.has(r.id) ? findModule(ctx.index, r.id, items.get(r.id)!.version) : undefined
    if (m) for (const dep of dependencyIds(m)) add(dep.id, dep.reason, r.id)
  }

  const latest = latestModules(ctx.index)
  const planned = [...items.values()]
  const installedModules = ctx.installed.map(i => ({ installed: i, module: findModule(ctx.index, i.id, i.version) ?? latest.get(i.id) }))

  for (const item of planned) {
    const m = findModule(ctx.index, item.id, item.version)!
    if (!satisfiesAppliance(m.requires?.appliance, ctx.applianceVersion)) {
      blockers.push({ code: 'E_APPLIANCE_VERSION', module: item.id, other: m.requires?.appliance })
    }
    const others: { id: string, conflicts: string[] }[] = [
      ...planned.filter(p => p.id !== item.id).map(p => ({ id: p.id, conflicts: findModule(ctx.index, p.id, p.version)?.conflicts ?? [] })),
      ...installedModules.map(i => ({ id: i.installed.id, conflicts: i.module?.conflicts ?? [] })),
    ]
    for (const o of others) {
      if ((m.conflicts.includes(o.id) || o.conflicts.includes(item.id))
        && !blockers.some(b => b.code === 'E_CONFLICT' && [b.module, b.other].includes(item.id) && [b.module, b.other].includes(o.id))) {
        blockers.push({ code: 'E_CONFLICT', module: item.id, other: o.id })
      }
    }
    if (item.hostname) {
      const taken = [
        ...planned.filter(p => p.id !== item.id && p.hostname === item.hostname).map(p => p.id),
        ...installedModules.filter(i => i.module?.type === 'service' && i.module.hostname === item.hostname).map(i => i.installed.id),
      ]
      if (taken.length && !blockers.some(b => b.code === 'E_HOSTNAME' && taken.includes(b.module ?? ''))) {
        blockers.push({ code: 'E_HOSTNAME', module: item.id, other: taken[0] })
      }
      if (!ctx.dns) warnings.push({ code: 'W_DNS_UNKNOWN', module: item.id })
    }
    if (item.hostname && ctx.dns) {
      const fqdn = ctx.dns.fqdn
      const name = fqdn ? `${item.hostname}.${fqdn}` : null
      const wildcard = ctx.dns.records.filter(r => r.name === `*.${fqdn}`)
      const own = ctx.dns.records.filter(r => r.name === name)
      const records = own.length ? own : wildcard
      if (!records.length || records.some(r => !r.ok)) warnings.push({ code: 'W_DNS', module: item.id, other: name ?? undefined })
    }
  }

  const licensesToAccept = planned.filter(p => p.needs_acceptance).map(p => p.id)
  const missing = licensesToAccept.filter(id => !accepted.has(id))
  if (missing.length) blockers.push({ code: 'E_LICENSE_REQUIRED', other: missing.join(',') })

  if (!ctx.machine) warnings.push({ code: 'W_RESOURCES_UNKNOWN' })
  const checks = resourceChecks(
    planned,
    installedModules.filter(i => i.module).map(i => ({ module: i.module!, enabled: i.installed.enabled })),
    ctx.machine,
  )
  for (const c of checks) if (!c.ok) blockers.push({ code: 'E_RESOURCES', other: c.kind })

  const sysctl = planned.flatMap(p => Object.entries(findModule(ctx.index, p.id, p.version)?.needs?.sysctl ?? {})
    .map(([key, value]) => ({ module: p.id, key, value })))

  return {
    ok: blockers.length === 0 && planned.length > 0,
    items: planned,
    skipped,
    checks,
    blockers,
    warnings,
    licenses_to_accept: licensesToAccept,
    sysctl,
  }
}

/** Modules installés qui dépendent de `id` : son retrait est bloqué (G1). */
export function dependentsOf(id: string, ctx: Pick<PlanContext, 'index' | 'installed'>): string[] {
  return ctx.installed
    .filter(i => i.id !== id)
    .filter((i) => {
      const m = findModule(ctx.index, i.id, i.version) ?? latestModules(ctx.index).get(i.id)
      return !!m && dependencyIds(m).some(d => d.id === id)
    })
    .map(i => i.id)
}
