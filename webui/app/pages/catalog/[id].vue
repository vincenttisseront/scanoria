<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'un module : licence et restrictions, ressources et compatibilité,
dépendances (G1), formulaire d'options généré (G3), installation avec plan,
banc d'essai (F12), activation, mise à jour et désinstallation (modale
irréversible : garder ou supprimer les données).
-->

<script setup lang="ts">
import { managesAdmin } from '#shared/admin-access'
import type { DnsStatus, FeedStatus, InstallPlan, InstalledModule, ModuleOperation, ModuleSummary } from '~/composables/useCatalog'

interface ModuleDetail {
  module: ModuleSummary | null
  options_schema: unknown
  options_i18n: Record<string, unknown> | null
  versions: string[]
  installed: InstalledModule | null
  update_available: string | null
  update_license: ModuleSummary['license'] | null
  plan: InstallPlan | null
  dependents: string[]
  feed: FeedStatus | null
  operations: ModuleOperation[]
  dns: DnsStatus | null
}

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const { t } = useI18n()
const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const text = useModuleText()
const { api, errorMessage } = useApi()
const { data: catalog, busy: catalogBusy, refresh: refreshCatalog } = useCatalog()

const detail = ref<ModuleDetail | null>(null)
const loadError = ref('')
async function load() {
  try {
    detail.value = await api<ModuleDetail>(`/api/catalog/modules/${encodeURIComponent(id.value)}`)
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
}
onMounted(load)
// useCatalog interroge l'état toutes les 5 s pendant une opération : chaque
// opération commencée ou terminée (lancée ici, depuis le catalogue ou un pack)
// recharge la fiche, pour que statut et boutons suivent sans recharger la page.
watch(() => (catalog.value?.operations ?? []).map(o => `${o.id}:${o.finished_at ?? ''}`).join('|'), (now, before) => {
  if (before !== undefined && now !== before) void load()
})
async function reload() {
  await Promise.all([load(), refreshCatalog()])
}

const title = computed(() => detail.value?.module?.name ?? detail.value?.installed?.id ?? id.value)
useHead({ title })

const m = computed(() => detail.value?.module ?? null)
const inst = computed(() => detail.value?.installed ?? null)
const names = computed(() => Object.fromEntries((catalog.value?.modules ?? []).map(x => [x.id, x.name])))
const installedIds = computed(() => (catalog.value?.modules ?? []).filter(x => x.installed).map(x => x.id))
const appUrl = computed(() => {
  if (inst.value?.route?.url) return inst.value.route.url
  const fqdn = detail.value?.dns?.fqdn
  return m.value?.hostname && fqdn ? `https://${m.value.hostname}.${fqdn}` : null
})
const dnsRecord = computed(() => {
  const fqdn = detail.value?.dns?.fqdn
  if (!m.value?.hostname || !fqdn) return null
  const records = detail.value!.dns!.records
  const own = records.filter(r => r.name === `${m.value!.hostname}.${fqdn}`)
  const list = own.length ? own : records.filter(r => r.name === `*.${fqdn}`)
  return list.length ? list.every(r => r.ok) : null
})

// --- Options et installation ---
const options = ref<Record<string, unknown>>({})
const optionsValid = ref(true)
const installOpen = ref(false)
const installRequest = computed(() => ({ modules: [{ id: id.value, options: options.value }] }))

// --- Activation ---
const stateModal = ref(false)
const stateReq = useHelperRequest()
async function setEnabled(enabled: boolean) {
  await stateReq.run(`/api/catalog/modules/${id.value}/state`, { enabled })
  stateModal.value = false
  await reload()
}

// --- Mise à jour ---
const updateModal = ref(false)
const updateReq = useHelperRequest()
async function update() {
  const restricted = !!detail.value?.update_license && detail.value.update_license.restrictions !== 'none'
  await updateReq.run(`/api/catalog/modules/${id.value}/update`, {
    version: detail.value?.update_available ?? undefined,
    accept_licenses: restricted ? [id.value] : [],
  }, { timeoutMs: 60 * 60_000 })
  updateModal.value = false
  await reload()
}

// --- Base d'un module feed : âge et mise à jour immédiate ---
const feedReq = useHelperRequest()
const feedAgeDays = computed(() => {
  const at = detail.value?.feed?.updated_at
  return at ? Math.max(0, Math.floor((Date.now() - Date.parse(at)) / 86_400_000)) : null
})
async function refreshFeed() {
  await feedReq.run('/api/catalog/feeds/refresh', { ids: [id.value] }, { timeoutMs: 60 * 60_000 })
  await reload()
}

// --- Désinstallation ---
const uninstallModal = ref(false)
const keepData = ref<'keep' | 'delete'>('keep')
const deleteAck = ref(false)
const uninstallReq = useHelperRequest()
watch(uninstallModal, (v) => {
  if (v) {
    keepData.value = 'keep'
    deleteAck.value = false
  }
})
const keepItems = computed(() => [
  { label: t('catalog.detail.keepData'), value: 'keep', description: t('catalog.detail.keepDataHelp') },
  { label: t('catalog.detail.deleteData'), value: 'delete', description: t('catalog.detail.deleteDataHelp') },
])
async function uninstall() {
  await uninstallReq.run(`/api/catalog/modules/${id.value}/uninstall`, { keep_data: keepData.value === 'keep' })
  uninstallModal.value = false
  await reload()
}

const updateAck = computed(() => {
  const l = detail.value?.update_license
  if (!l || l.restrictions === 'none') return undefined
  return t('catalog.detail.updateLicense', { version: detail.value!.update_available ?? '', spdx: l.spdx, restriction: text.restrictionLabel(l.restrictions) })
})
const dependentNames = computed(() => (detail.value?.dependents ?? []).map(d => names.value[d] ?? d).join(', '))
const ownRunning = computed(() => stateReq.running.value || updateReq.running.value || uninstallReq.running.value
  || feedReq.running.value)
// Une opération lancée ailleurs (autre onglet, pack) bloque aussi les actions de la fiche.
const anyRunning = computed(() => ownRunning.value || catalogBusy.value)
interface TestbedCase { rule: string | null, category: string | null, min: number, found: number, ok: boolean }
const testbedCases = computed<TestbedCase[]>(() => {
  const d = inst.value?.testbed?.details
  return Array.isArray(d) ? d.filter((c): c is TestbedCase => !!c && typeof c === 'object' && typeof c.found === 'number') : []
})
const testbedDetails = computed(() => {
  const d = inst.value?.testbed?.details
  if (d === undefined || d === null || Array.isArray(d)) return ''
  return typeof d === 'string' ? d : JSON.stringify(d, null, 2)
})
</script>

<template>
  <PageShell :title="title">
    <template #actions>
      <UButton
        to="/catalog"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('catalog.title')"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!detail"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="detail">
      <UAlert
        v-if="!m"
        color="warning"
        variant="subtle"
        :title="t('catalog.orphans.help')"
      />

      <div
        v-if="m"
        class="grid gap-4 md:grid-cols-2"
      >
        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ m.name }} {{ m.version }}
            </h2>
            <p class="text-sm text-muted">
              {{ text.typeLabel(m.type) }} · {{ m.categories.join(', ') }}
            </p>
          </template>
          <p
            v-if="m.description"
            class="text-sm"
          >
            {{ text.localized(m.description) }}
          </p>
          <ul class="mt-3 space-y-1 text-sm">
            <li>
              {{ t('catalog.detail.license') }} : {{ m.license.spdx }}
              <UBadge
                :color="m.license.restrictions === 'none' ? 'success' : 'warning'"
                variant="subtle"
                class="ml-1"
                :label="text.restrictionLabel(m.license.restrictions)"
              />
            </li>
            <li
              v-if="m.license.note"
              class="text-muted"
            >
              {{ m.license.note }}
            </li>
            <li v-if="m.license.url">
              <ULink
                :to="m.license.url"
                target="_blank"
                rel="noopener noreferrer"
              >
                {{ t('catalog.detail.licenseText') }}
              </ULink>
            </li>
            <li v-if="m.upstream?.homepage || m.upstream?.source">
              {{ t('catalog.detail.upstream') }} :
              <ULink
                v-if="m.upstream?.homepage"
                :to="m.upstream.homepage"
                target="_blank"
                rel="noopener noreferrer"
              >
                {{ t('catalog.detail.homepage') }}
              </ULink>
              <template v-if="m.upstream?.homepage && m.upstream?.source">
                ·
              </template>
              <ULink
                v-if="m.upstream?.source"
                :to="m.upstream.source"
                target="_blank"
                rel="noopener noreferrer"
              >
                {{ t('catalog.detail.source') }}
              </ULink>
            </li>
            <li v-if="detail.versions.length > 1">
              {{ t('catalog.detail.versions', { list: detail.versions.join(', ') }) }}
            </li>
          </ul>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('catalog.detail.resourcesTitle') }}
            </h2>
          </template>
          <p class="text-sm">
            {{ t('catalog.list.resourcesValue', { ram: fmt.gb(m.resources.min_ram_mb), cpu: m.resources.min_cpu, disk: fmt.gb(m.resources.disk_mb) }) }}
          </p>
          <ul
            v-if="detail.plan"
            class="mt-2 space-y-1 text-sm"
          >
            <li
              v-for="c in detail.plan.checks"
              :key="c.kind"
              class="flex items-center gap-2"
            >
              <UIcon
                :name="c.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
                :class="c.ok ? 'text-success' : 'text-error'"
              />
              {{ text.checkText(c) }}
            </li>
          </ul>
          <p
            v-for="(value, key) in m.sysctl"
            :key="key"
            class="mt-2 text-sm text-muted"
          >
            {{ t('catalog.plan.sysctl', { module: m.name, key: String(key), value: String(value) }) }}
          </p>
          <p
            v-if="m.postgres"
            class="mt-2 text-sm text-muted"
          >
            {{ t('catalog.detail.postgres') }}
          </p>
          <p
            v-if="m.hostname"
            class="mt-2 text-sm"
          >
            {{ t('catalog.detail.hostname') }} :
            <ULink
              v-if="appUrl && inst?.route"
              :to="appUrl"
              target="_blank"
              rel="noopener noreferrer"
            >
              {{ appUrl }}
            </ULink>
            <span v-else>{{ appUrl ?? `${m.hostname}.…` }}</span>
            <UBadge
              v-if="dnsRecord !== null"
              :color="dnsRecord ? 'success' : 'warning'"
              variant="subtle"
              class="ml-1"
              :label="dnsRecord ? t('catalog.dns.resolves') : t('catalog.dns.notResolving')"
            />
          </p>
        </UCard>
      </div>

      <ServiceAdminAccess
        v-if="inst?.status === 'healthy' && inst.enabled && managesAdmin(id)"
        :module-id="id"
        :name="title"
        :app-url="appUrl"
        :is-admin="isAdmin"
      />

      <UCard v-if="inst">
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.detail.installedTitle') }}
          </h2>
        </template>
        <ul class="space-y-1 text-sm">
          <li>{{ t('catalog.detail.installedVersion', { version: inst.version, date: fmt.date(inst.installed_at) }) }}</li>
          <li>
            {{ t('catalog.list.status') }} :
            <UBadge
              :color="inst.status === 'healthy' ? 'success' : inst.status === 'failed' ? 'error' : 'neutral'"
              variant="subtle"
              :label="text.statusLabel(inst.status)"
            />
            <UBadge
              v-if="!inst.enabled"
              color="neutral"
              variant="outline"
              class="ml-1"
              :label="t('catalog.detail.disabled')"
            />
          </li>
          <li
            v-if="text.lastError(inst)"
            class="text-error"
          >
            {{ t('catalog.detail.lastError') }} : {{ text.lastError(inst) }}
          </li>
          <li v-if="detail.update_available">
            {{ t('catalog.list.updateAvailable', { version: detail.update_available }) }}
          </li>
        </ul>

        <div
          v-if="detail.feed"
          class="mt-4 rounded border p-3"
          :class="detail.feed.status === 'ok' ? 'border-default' : 'border-warning'"
          data-feed
        >
          <h3 class="text-sm font-semibold">
            {{ t('catalog.feed.title') }}
          </h3>
          <p class="text-sm">
            <template v-if="detail.feed.updated_at">
              {{ t('catalog.feed.updated', { date: fmt.date(detail.feed.updated_at), days: feedAgeDays ?? 0, size: detail.feed.size_mb ?? 0 }) }}
            </template>
            <template v-else>
              {{ t('catalog.feed.missing') }}
            </template>
          </p>
          <p
            v-if="detail.feed.status === 'stale' || detail.feed.status === 'failed'"
            class="text-sm text-warning"
          >
            {{ t('catalog.feed.lastFailure', { error: detail.feed.error ?? '?' }) }}
          </p>
          <p class="text-xs text-muted">
            {{ t('catalog.feed.help') }}
          </p>
          <div
            v-if="isAdmin"
            class="mt-2 space-y-1"
          >
            <UButton
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="outline"
              size="sm"
              :loading="feedReq.running.value"
              :disabled="anyRunning && !feedReq.running.value"
              :label="t('catalog.feed.refresh')"
              @click="refreshFeed"
            />
            <RequestProgress
              :active="feedReq.running.value"
              :label="feedReq.label.value"
            />
          </div>
        </div>

        <div
          class="mt-4 rounded border p-3"
          :class="inst.testbed?.passed === false ? 'border-error' : 'border-default'"
          data-testbed
        >
          <h3 class="text-sm font-semibold">
            {{ t('catalog.testbed.title') }}
          </h3>
          <p class="text-sm">
            <template v-if="!inst.testbed || inst.testbed.passed === null">
              {{ t('catalog.testbed.pending') }}
            </template>
            <template v-else-if="inst.testbed.passed">
              {{ t('catalog.testbed.passed', { date: fmt.date(inst.testbed.at) }) }}
            </template>
            <template v-else>
              {{ t('catalog.testbed.failed', { date: fmt.date(inst.testbed.at) }) }}
            </template>
          </p>
          <p class="text-xs text-muted">
            {{ t('catalog.testbed.help') }}
          </p>
          <ul
            v-if="testbedCases.length"
            class="mt-2 space-y-1 text-sm"
          >
            <li
              v-for="(c, i) in testbedCases"
              :key="i"
              class="flex items-center gap-2"
            >
              <UIcon
                :name="c.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
                :class="c.ok ? 'text-success' : 'text-error'"
              />
              {{ t('catalog.testbed.case', { what: c.rule ?? c.category ?? '?', found: c.found, min: c.min }) }}
            </li>
          </ul>
          <pre
            v-if="testbedDetails"
            class="mt-2 max-h-48 overflow-auto text-xs"
          >{{ testbedDetails }}</pre>
        </div>

        <ModuleBackups
          v-if="inst.type === 'service' || inst.type === 'runner'"
          :module="inst"
          :name="title"
          :admin="isAdmin"
          :busy="anyRunning"
          @done="reload"
        />

        <div
          v-if="isAdmin"
          class="mt-4 flex flex-wrap items-center gap-3"
        >
          <UButton
            v-if="inst.enabled"
            icon="i-lucide-pause"
            color="neutral"
            variant="outline"
            :loading="stateReq.running.value"
            :disabled="anyRunning && !stateReq.running.value"
            :label="t('catalog.detail.disable')"
            @click="stateModal = true"
          />
          <UButton
            v-else
            icon="i-lucide-play"
            color="neutral"
            variant="outline"
            :loading="stateReq.running.value"
            :disabled="anyRunning && !stateReq.running.value"
            :label="t('catalog.detail.enable')"
            @click="setEnabled(true)"
          />
          <UButton
            v-if="detail.update_available"
            icon="i-lucide-arrow-up-circle"
            :loading="updateReq.running.value"
            :disabled="anyRunning && !updateReq.running.value"
            :label="t('catalog.detail.update', { version: detail.update_available })"
            @click="updateModal = true"
          />
          <UButton
            icon="i-lucide-trash-2"
            color="error"
            variant="outline"
            :loading="uninstallReq.running.value"
            :disabled="(anyRunning && !uninstallReq.running.value) || detail.dependents.length > 0"
            :label="t('catalog.detail.uninstall')"
            @click="uninstallModal = true"
          />
        </div>
        <p
          v-if="isAdmin && detail.dependents.length"
          class="mt-2 text-sm text-muted"
        >
          {{ t('catalog.detail.dependentsBlock', { list: detail.dependents.map(d => names[d] ?? d).join(', ') }) }}
        </p>
        <div class="mt-2 space-y-1">
          <RequestProgress
            :active="stateReq.running.value"
            :label="stateReq.label.value"
          />
          <RequestProgress
            :active="updateReq.running.value"
            :label="updateReq.label.value"
          />
          <RequestProgress
            :active="uninstallReq.running.value"
            :label="uninstallReq.label.value"
          />
        </div>
      </UCard>

      <UsageModulePanel
        v-if="inst"
        :module-id="id"
        :names="names"
        :can-uninstall="isAdmin && !anyRunning"
        @uninstall="uninstallModal = true"
      />

      <UCard v-if="m">
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.options.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ inst ? t('catalog.options.installedHelp') : t('catalog.options.help') }}
          </p>
        </template>
        <ModuleOptionsForm
          v-if="!inst"
          v-model="options"
          :schema="detail.options_schema"
          :i18n="detail.options_i18n"
          :disabled="!isAdmin"
          @valid="v => optionsValid = v"
        />
        <ModuleOptionsForm
          v-else
          :model-value="inst.options"
          :schema="detail.options_schema"
          :i18n="detail.options_i18n"
          disabled
        />
        <template v-if="!inst">
          <UAlert
            v-for="(b, i) in (detail.plan?.blockers ?? []).filter(b => b.code !== 'E_LICENSE_REQUIRED')"
            :key="i"
            class="mt-4"
            color="warning"
            variant="subtle"
            :title="text.issueText(b)"
          />
          <div
            v-if="isAdmin"
            class="mt-4"
          >
            <UButton
              icon="i-lucide-download"
              :disabled="!optionsValid"
              :label="t('catalog.detail.install')"
              @click="installOpen = true"
            />
          </div>
        </template>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.graph.title') }}
          </h2>
        </template>
        <DependencyGraph
          :edges="catalog?.graph ?? []"
          :names="names"
          :installed="installedIds"
          :focus="id"
        />
        <p
          v-if="detail.dependents.length"
          class="mt-2 text-sm text-muted"
        >
          {{ t('catalog.detail.dependents', { list: detail.dependents.map(d => names[d] ?? d).join(', ') }) }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.operations.title') }}
          </h2>
        </template>
        <ModuleOperations :operations="detail.operations" />
      </UCard>
    </template>

    <InstallPlanModal
      v-model:open="installOpen"
      :title="t('catalog.detail.installTitle', { name: title })"
      :request="installRequest"
      @done="reload"
    />

    <ConfirmModal
      v-model:open="stateModal"
      :title="t('catalog.detail.disableTitle', { name: title })"
      :body="detail?.dependents.length ? t('catalog.detail.disableBodyDependents', { list: dependentNames }) : t('catalog.detail.disableBody')"
      :confirm-label="t('catalog.detail.disable')"
      color="warning"
      :loading="stateReq.running.value"
      @confirm="setEnabled(false)"
    />

    <ConfirmModal
      v-model:open="updateModal"
      :title="t('catalog.detail.updateTitle', { name: title, version: detail?.update_available ?? '' })"
      :body="t('catalog.detail.updateBody')"
      :ack="updateAck"
      :confirm-label="t('catalog.detail.update', { version: detail?.update_available ?? '' })"
      :loading="updateReq.running.value"
      @confirm="update"
    />

    <UModal
      v-model:open="uninstallModal"
      :title="t('catalog.detail.uninstallTitle', { name: title })"
      :dismissible="!uninstallReq.running.value"
    >
      <template #body>
        <div class="space-y-4">
          <p class="text-sm text-muted">
            {{ t('catalog.detail.uninstallBody') }}
          </p>
          <URadioGroup
            v-model="keepData"
            :items="keepItems"
          />
          <UCheckbox
            v-if="keepData === 'delete'"
            v-model="deleteAck"
            :label="t('catalog.detail.deleteAck')"
          />
          <RequestProgress
            :active="uninstallReq.running.value"
            :label="uninstallReq.label.value"
          />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="uninstallReq.running.value"
            :label="t('common.cancel')"
            @click="uninstallModal = false"
          />
          <UButton
            color="error"
            :loading="uninstallReq.running.value"
            :disabled="keepData === 'delete' && !deleteAck"
            :label="t('catalog.detail.uninstallConfirm')"
            @click="uninstall"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
