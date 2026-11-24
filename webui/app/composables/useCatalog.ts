// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Catalogue des modules (lecture seule) : vue renvoyée par GET /api/catalog,
// rafraîchie toutes les 5 s pendant une opération, toutes les 30 s sinon.

/** Texte traduit du catalogue (description d'un module ou d'un pack). */
export interface LocalizedText { fr: string, en: string }

export type ModuleType = 'scanner' | 'service' | 'feed' | 'runner'
export type Restriction = 'none' | 'private-code-forbidden' | 'no-redistribution' | 'other'
export type ModuleStatus = 'installing' | 'testing' | 'healthy' | 'failed' | 'disabled' | 'removing'

export interface ModuleLicense { spdx: string, url?: string, restrictions: Restriction, note?: string }
export interface ModuleResources { min_ram_mb: number, min_cpu: number, disk_mb: number }

export interface InstalledModule {
  id: string
  version: string
  type: ModuleType
  status: ModuleStatus
  enabled: boolean
  installed_at?: string | null
  options: Record<string, unknown>
  testbed?: { passed: boolean | null, at?: string | null, details?: unknown } | null
  route?: { hostname: string, url: string } | null
  last_error?: string | { code?: string, message?: string } | null
}

export interface PlanIssue { code: string, module?: string, other?: string, options?: { key: string, code: string }[] }
export interface ResourceCheck { kind: 'ram' | 'cpu' | 'disk', needed: number, available: number | null, ok: boolean }

export interface PlanItem {
  id: string
  name: string
  version: string
  type: ModuleType
  reason: 'requested' | 'dependency' | 'feed'
  required_by: string[]
  license: ModuleLicense
  needs_acceptance: boolean
  options: Record<string, unknown>
  changed_options: string[]
  resources: ModuleResources
  hostname: string | null
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

export interface ModuleSummary {
  id: string
  name: string
  type: ModuleType
  version: string
  description: LocalizedText | null
  categories: string[]
  license: ModuleLicense
  upstream: { homepage?: string, source?: string } | null
  resources: ModuleResources
  hostname: string | null
  requires: { modules: string[], feeds: string[], appliance: string | null }
  conflicts: string[]
  sysctl: Record<string, string | number>
  postgres: boolean
  has_testbed: boolean
}

export interface CatalogEntry extends ModuleSummary {
  installed: InstalledModule | null
  update_available: string | null
  compatible: boolean
  blockers: PlanIssue[]
  auto_added: string[]
  dependents: string[]
}

export interface ModuleOperation {
  id: string
  request_id?: string | null
  kind: string
  module?: string | null
  step?: string | null
  progress?: number | null
  started_at?: string | null
  finished_at?: string | null
  result?: unknown
  message?: string | null
}

export interface DnsRecord { name: string, type: 'A' | 'AAAA', expected: string, resolved: string[], ok: boolean }
export interface DnsStatus { fqdn: string | null, checked_at?: string | null, records: DnsRecord[] }

export interface CatalogPack {
  id: string
  name: string
  modules: string[]
  technologies: string[]
  description?: LocalizedText
  unknown_modules: string[]
  installed_modules: string[]
  pending_modules: string[]
  plan: InstallPlan | null
}

export interface CatalogView {
  index: { available: boolean, version: number | null, generated_at: string | null, rejected: number }
  state_available: boolean
  machine: { cpu_count: number, memory_mb: number, disks: { mount: string, size_mb: number, avail_mb: number }[] } | null
  appliance_version: string
  modules: CatalogEntry[]
  orphans: InstalledModule[]
  packs: CatalogPack[]
  graph: { from: string, to: string, kind: 'module' | 'feed' | 'conflict' }[]
  recommended: { ids: string[], first_access: boolean, plan: InstallPlan | null }
  operations: ModuleOperation[]
  dns: DnsStatus | null
}

export const isRunningOperation = (o: ModuleOperation) => !o.finished_at

export function useCatalog() {
  const { api } = useApi()
  const data = ref<CatalogView | null>(null)
  const error = ref(false)
  let timer: ReturnType<typeof setTimeout> | undefined
  let stopped = false

  async function refresh(): Promise<void> {
    try {
      data.value = await api<CatalogView>('/api/catalog')
      error.value = false
    }
    catch {
      error.value = true
    }
  }

  const busy = computed(() => !!data.value?.operations.some(isRunningOperation))

  function schedule() {
    if (stopped) return
    timer = setTimeout(async () => {
      await refresh()
      schedule()
    }, busy.value ? 5000 : 30_000)
  }

  onMounted(async () => {
    await refresh()
    schedule()
  })
  onBeforeUnmount(() => {
    stopped = true
    if (timer) clearTimeout(timer)
  })

  return { data, error, busy, refresh }
}
