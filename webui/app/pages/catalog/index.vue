<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Catalogue des modules : sélection conseillée au premier accès (§ 5.3), packs
avec contrôle global des ressources (F11), liste des modules (licence,
restrictions, ressources, compatibilité), opérations en cours (l'historique
est dans le journal d'audit) et graphe des dépendances (G1).
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { isRunningOperation, type CatalogEntry, type CatalogPack, type ModuleOperation } from '~/composables/useCatalog'
import { FEED_ALERT_DAYS, feedAgeDays } from '#shared/analysis'

/** § 9 : base plus vieille que le seuil d'alerte (7 jours), signalée dans la liste. */
function feedTooOld(updatedAt: string | null | undefined): boolean {
  const d = feedAgeDays(updatedAt)
  return d !== null && d > FEED_ALERT_DAYS
}

const { t } = useI18n()
useHead({ title: computed(() => t('catalog.title')) })

const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const text = useModuleText()
const { data, error, refresh } = useCatalog()

// --- Actualisation de l'index ---
const refreshReq = useHelperRequest()
async function refreshCatalog() {
  await refreshReq.run('/api/catalog/refresh', {})
  await refresh()
}

// --- Installation (sélection, pack ou module) ---
const installOpen = ref(false)
const installTitle = ref('')
const installRequest = ref<{ modules: { id: string }[] } | { pack: string } | null>(null)
function openInstall(title: string, request: { modules: { id: string }[] } | { pack: string }) {
  installTitle.value = title
  installRequest.value = request
  installOpen.value = true
}
function installRecommended() {
  openInstall(t('catalog.recommended.title'), { modules: data.value!.recommended.ids.map(id => ({ id })) })
}
function installPack(pack: CatalogPack) {
  openInstall(t('catalog.packs.installTitle', { name: pack.name }), { pack: pack.id })
}
async function onInstalled() {
  await refresh()
}

// --- Sélection conseillée : masquable (préférence du navigateur) ---
const HIDE_KEY = 'scanoria.catalog.hideRecommended'
const hideRecommended = ref(false)
onMounted(() => {
  try {
    hideRecommended.value = localStorage.getItem(HIDE_KEY) === '1'
  }
  catch {
    // stockage indisponible : la sélection reste affichée
  }
})
function dismissRecommended() {
  hideRecommended.value = true
  try {
    localStorage.setItem(HIDE_KEY, '1')
  }
  catch {
    // sans conséquence
  }
}
const showRecommended = computed(() => !!data.value?.recommended.ids.length
  && (data.value.recommended.first_access || !hideRecommended.value))
const names = computed(() => Object.fromEntries((data.value?.modules ?? []).map(m => [m.id, m.name])))
const installedIds = computed(() => (data.value?.modules ?? []).filter(m => m.installed).map(m => m.id))

// --- Opérations : seules celles en cours sont affichées ; l'historique est
// dans le journal d'audit. Un échec est signalé par une notification : à
// l'ouverture s'il date de moins d'une heure, puis dès qu'une opération
// suivie pendant la visite échoue.
const toast = useToast()
const runningOperations = computed(() => (data.value?.operations ?? []).filter(isRunningOperation))
const FAILURE_RECENT_MS = 3_600_000
let seenOperations: Set<string> | null = null
function notifyFailure(op: ModuleOperation) {
  toast.add({
    title: text.operationLabel(op),
    description: op.message ? `${t('catalog.operations.failed')} · ${op.message}` : t('catalog.operations.failed'),
    color: 'error',
    icon: 'i-lucide-circle-x',
  })
}
watch(() => data.value?.operations, (ops) => {
  if (!ops) return
  const finished = ops.filter(o => !isRunningOperation(o))
  if (seenOperations === null) {
    const last = [...finished].sort((a, b) => (b.finished_at ?? '').localeCompare(a.finished_at ?? ''))[0]
    if (last?.result === 'failed' && Date.now() - Date.parse(last.finished_at!) < FAILURE_RECENT_MS) notifyFailure(last)
  }
  else {
    for (const o of finished) if (o.result === 'failed' && !seenOperations.has(o.id)) notifyFailure(o)
  }
  seenOperations = new Set(finished.map(o => o.id))
})

// --- Filtres ---
const search = ref('')
const typeFilter = ref<string>('all')
const typeItems = computed(() => [
  { label: t('catalog.filters.allTypes'), value: 'all' },
  ...['scanner', 'service', 'feed', 'runner'].map(v => ({ label: text.typeLabel(v), value: v })),
])
const rows = computed(() => (data.value?.modules ?? []).filter((m) => {
  if (typeFilter.value !== 'all' && m.type !== typeFilter.value) return false
  const q = search.value.trim().toLowerCase()
  if (!q) return true
  return [m.id, m.name, text.localized(m.description), ...m.categories].some(s => s.toLowerCase().includes(q))
}))

function statusOf(m: CatalogEntry): { label: string, color: 'success' | 'error' | 'warning' | 'neutral' | 'info' } {
  if (m.installed) {
    const s = m.installed.status
    if (s === 'healthy' && m.installed.enabled) return { label: text.statusLabel('healthy'), color: 'success' }
    if (s === 'failed') return { label: text.statusLabel('failed'), color: 'error' }
    if (!m.installed.enabled || s === 'disabled') return { label: text.statusLabel('disabled'), color: 'neutral' }
    return { label: text.statusLabel(s), color: 'info' }
  }
  if (!m.compatible) return { label: t('catalog.list.incompatible'), color: 'warning' }
  return { label: t('catalog.list.available'), color: 'neutral' }
}

const columns = computed<TableColumn<CatalogEntry>[]>(() => [
  { accessorKey: 'name', header: t('catalog.list.module') },
  { accessorKey: 'type', header: t('catalog.list.type') },
  { id: 'license', header: t('catalog.list.license') },
  { id: 'resources', header: t('catalog.list.resources') },
  { id: 'status', header: t('catalog.list.status') },
])

// Complet seulement si chaque module du pack est installé (un module absent du
// catalogue n'est ni installable ni installé).
const packComplete = (p: CatalogPack) => p.modules.every(id => p.installed_modules.includes(id))
const packResourcesOk = (p: CatalogPack) => !p.plan || p.plan.checks.every(c => c.ok)
</script>

<template>
  <PageShell :title="t('catalog.title')">
    <template #actions>
      <UButton
        to="/catalog/dns"
        icon="i-lucide-globe"
        color="neutral"
        variant="ghost"
        :label="t('catalog.dnsLink')"
      />
      <UButton
        v-if="isAdmin"
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="outline"
        :loading="refreshReq.running.value"
        :label="t('catalog.refresh')"
        @click="refreshCatalog"
      />
    </template>

    <RequestProgress
      :active="refreshReq.running.value"
      :label="refreshReq.label.value"
    />

    <div
      v-if="!data && !error"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      :title="t('errors.generic')"
    />

    <template v-if="data">
      <UAlert
        v-if="!data.index.available"
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        :title="t('catalog.indexMissing')"
        :description="t('catalog.indexMissingHelp')"
      />
      <UAlert
        v-else-if="data.index.rejected"
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        :title="t('catalog.indexRejected', { count: data.index.rejected })"
      />
      <UAlert
        v-if="!data.state_available"
        color="neutral"
        variant="subtle"
        icon="i-lucide-info"
        :title="t('catalog.stateMissing')"
      />

      <UCard
        v-if="showRecommended"
        data-recommended
      >
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <h2 class="font-semibold">
              {{ t('catalog.recommended.title') }}
            </h2>
            <UButton
              v-if="!data.recommended.first_access"
              color="neutral"
              variant="ghost"
              size="xs"
              icon="i-lucide-x"
              :aria-label="t('catalog.recommended.hide')"
              @click="dismissRecommended"
            />
          </div>
        </template>
        <p class="text-sm">
          {{ t('catalog.recommended.why') }}
        </p>
        <div class="mt-3 flex flex-wrap gap-2">
          <UBadge
            v-for="id in data.recommended.ids"
            :key="id"
            color="neutral"
            variant="subtle"
            :label="names[id] ?? id"
          />
        </div>
        <p
          v-if="data.recommended.plan && data.recommended.plan.items.length > data.recommended.ids.length"
          class="mt-2 text-sm text-muted"
        >
          {{ t('catalog.recommended.withDeps', { count: data.recommended.plan.items.length - data.recommended.ids.length }) }}
        </p>
        <div
          v-if="isAdmin"
          class="mt-4"
        >
          <UButton
            icon="i-lucide-download"
            :label="t('catalog.recommended.install')"
            @click="installRecommended"
          />
        </div>
        <p
          v-else
          class="mt-3 text-sm text-muted"
        >
          {{ t('common.adminOnly') }}
        </p>
      </UCard>

      <ModuleOperations
        v-if="runningOperations.length"
        :operations="runningOperations"
        data-running-operations
      />

      <div
        v-if="data.packs.length"
        class="space-y-3"
      >
        <h2 class="font-semibold">
          {{ t('catalog.packs.title') }}
        </h2>
        <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          <UCard
            v-for="p in data.packs"
            :key="p.id"
            :data-pack="p.id"
          >
            <template #header>
              <h3 class="font-semibold">
                {{ p.name }}
              </h3>
              <p
                v-if="p.technologies.length"
                class="text-sm text-muted"
              >
                {{ p.technologies.join(', ') }}
              </p>
            </template>
            <p
              v-if="p.description"
              class="mb-2 text-sm"
            >
              {{ text.localized(p.description) }}
            </p>
            <div class="flex flex-wrap gap-1">
              <UBadge
                v-for="id in p.modules"
                :key="id"
                :color="p.installed_modules.includes(id) ? 'success' : 'neutral'"
                :icon="p.installed_modules.includes(id) ? 'i-lucide-check' : undefined"
                variant="subtle"
                :label="names[id] ?? id"
              />
            </div>
            <p
              v-if="packComplete(p)"
              class="mt-3 text-sm text-success"
            >
              {{ t('catalog.packs.complete') }}
            </p>
            <template v-else-if="p.plan">
              <p
                class="mt-3 text-sm"
                :class="packResourcesOk(p) ? 'text-muted' : 'text-error'"
              >
                {{ packResourcesOk(p) ? t('catalog.packs.resourcesOk') : t('catalog.packs.resourcesKo') }}
              </p>
              <ul
                v-if="!packResourcesOk(p)"
                class="text-sm text-error"
              >
                <li
                  v-for="c in p.plan.checks.filter(c => !c.ok)"
                  :key="c.kind"
                >
                  {{ text.checkText(c) }}
                </li>
              </ul>
            </template>
            <p
              v-if="p.unknown_modules.length"
              class="mt-2 text-sm text-warning"
            >
              {{ t('catalog.packs.unknown', { list: p.unknown_modules.join(', ') }) }}
            </p>
            <template #footer>
              <UButton
                v-if="isAdmin && p.pending_modules.length"
                icon="i-lucide-package-plus"
                :label="t('catalog.packs.install', { count: p.pending_modules.length })"
                @click="installPack(p)"
              />
            </template>
          </UCard>
        </div>
      </div>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-3">
            <h2 class="font-semibold">
              {{ t('catalog.list.title') }}
            </h2>
            <div class="flex flex-wrap gap-2">
              <UInput
                v-model="search"
                icon="i-lucide-search"
                :placeholder="t('catalog.filters.search')"
                class="w-56"
              />
              <USelect
                v-model="typeFilter"
                :items="typeItems"
                class="w-40"
              />
            </div>
          </div>
        </template>
        <UTable
          :data="rows"
          :columns="columns"
          :empty="t('catalog.list.empty')"
        >
          <template #name-cell="{ row }">
            <NuxtLink
              :to="`/catalog/${row.original.id}`"
              class="font-medium hover:underline"
            >
              {{ row.original.name }}
            </NuxtLink>
            <span class="text-muted"> {{ row.original.version }}</span>
            <p
              v-if="row.original.description"
              class="max-w-md truncate text-sm text-muted"
            >
              {{ text.localized(row.original.description) }}
            </p>
          </template>
          <template #type-cell="{ row }">
            {{ text.typeLabel(row.original.type) }}
            <p class="text-xs text-muted">
              {{ row.original.categories.join(', ') }}
            </p>
          </template>
          <template #license-cell="{ row }">
            {{ row.original.license.spdx }}
            <UBadge
              v-if="row.original.license.restrictions !== 'none'"
              color="warning"
              variant="subtle"
              class="ml-1"
              :label="text.restrictionLabel(row.original.license.restrictions)"
            />
          </template>
          <template #resources-cell="{ row }">
            <span class="text-sm">{{ t('catalog.list.resourcesValue', { ram: fmt.gb(row.original.resources.min_ram_mb), cpu: row.original.resources.min_cpu, disk: fmt.gb(row.original.resources.disk_mb) }) }}</span>
          </template>
          <template #status-cell="{ row }">
            <UBadge
              :color="statusOf(row.original).color"
              variant="subtle"
              :label="statusOf(row.original).label"
            />
            <UBadge
              v-if="row.original.update_available"
              color="info"
              variant="subtle"
              class="ml-1"
              :label="t('catalog.list.updateAvailable', { version: row.original.update_available })"
            />
            <p
              v-if="row.original.feed"
              class="mt-1 text-xs"
              :class="row.original.feed.status === 'ok' && !feedTooOld(row.original.feed.updated_at) ? 'text-muted' : 'text-warning'"
              data-feed-age
            >
              <UIcon
                v-if="feedTooOld(row.original.feed.updated_at)"
                name="i-lucide-clock-alert"
                class="align-middle"
                data-feed-too-old
              />
              {{ row.original.feed.updated_at
                ? t('catalog.feed.age', { date: fmt.date(row.original.feed.updated_at) })
                : t('catalog.feed.none') }}
            </p>
            <p
              v-if="!row.original.installed && row.original.blockers.length"
              class="mt-1 max-w-xs text-xs text-warning"
            >
              {{ text.issueText(row.original.blockers[0]!) }}
            </p>
          </template>
        </UTable>
      </UCard>

      <UCard v-if="data.orphans.length">
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.orphans.title') }}
          </h2>
        </template>
        <p class="mb-2 text-sm text-muted">
          {{ t('catalog.orphans.help') }}
        </p>
        <ul class="text-sm">
          <li
            v-for="o in data.orphans"
            :key="o.id"
          >
            <NuxtLink
              :to="`/catalog/${o.id}`"
              class="hover:underline"
            >
              {{ o.id }} {{ o.version }}
            </NuxtLink>
            — {{ text.statusLabel(o.status) }}
          </li>
        </ul>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.graph.title') }}
          </h2>
        </template>
        <DependencyGraph
          :edges="data.graph"
          :names="names"
          :installed="installedIds"
        />
      </UCard>
    </template>

    <InstallPlanModal
      v-model:open="installOpen"
      :title="installTitle"
      :request="installRequest"
      @done="onInstalled"
    />
  </PageShell>
</template>
