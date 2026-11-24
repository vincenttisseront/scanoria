<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Onglet « SBOM » d'une analyse (0.5, contrat 14) : composants relevés par Syft
(purl, version, écosystème, licences, dépendance directe, fichiers d'origine),
filtrés, triés et paginés côté serveur ; export CycloneDX ; lien vers le
projet Dependency-Track quand le SBOM y a été envoyé. La couverture (G15)
dit combien de composants sans purl ont été ignorés. Rien n'est affiché
comme HTML : noms et licences viennent de l'outil.
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h } from 'vue'
import SbomLicenseDecision from './LicenseDecision.vue'

const props = defineProps<{ scanId: string }>()
const { t } = useI18n()
const { api, errorMessage } = useApi()

interface Component {
  purl: string
  ecosystem: string
  name: string
  version: string | null
  licenses: string[]
  direct: boolean | null
  paths: string[]
}
interface SbomPage {
  total: number
  matched: number
  page: number
  per_page: number
  components: Component[]
  ecosystems: { ecosystem: string, count: number }[]
  licenses: { license: string, count: number }[]
  coverage: { components?: number, ignored_no_purl?: number, ignored_invalid_purl?: number, direct_known?: boolean, module?: string | null } | null
  dtrack: { project: string, url: string | null } | null
}

const PER_PAGE = 50
const SORTS = ['name', 'ecosystem', 'version', 'license', 'direct'] as const
const data = ref<SbomPage | null>(null)
const loading = ref(false)
const error = ref('')
const page = ref(1)
const filters = reactive({ q: '', ecosystem: 'all', license: 'all', direct: 'all', sort: 'name' as (typeof SORTS)[number], order: 'asc' as 'asc' | 'desc' })

// Seule la réponse de la dernière requête est affichée (filtres changés en cours de route).
let seq = 0
async function load() {
  const mine = ++seq
  loading.value = true
  const query: Record<string, string | number> = { page: page.value, per_page: PER_PAGE, sort: filters.sort, order: filters.order }
  if (filters.q.trim()) query.q = filters.q.trim().slice(0, 200)
  if (filters.ecosystem !== 'all') query.ecosystem = filters.ecosystem
  if (filters.license !== 'all') query.license = filters.license
  if (filters.direct !== 'all') query.direct = filters.direct
  try {
    const res = await api<SbomPage>(`/api/scans/${encodeURIComponent(props.scanId)}/sbom`, { query })
    if (mine !== seq) return
    data.value = res
    error.value = ''
  }
  catch (err) {
    if (mine === seq) error.value = errorMessage(err)
  }
  finally {
    if (mine === seq) loading.value = false
  }
}

let debounce: ReturnType<typeof setTimeout> | undefined
watch(filters, () => {
  clearTimeout(debounce)
  debounce = setTimeout(() => {
    if (page.value !== 1) page.value = 1
    else void load()
  }, 250)
})
// Décision de licence de chaque composant (F8, chantier B), par purl ; sans
// elle (erreur, droits), la colonne garde les licences brutes.
type Decision = { purl: string, decision: 'allowed' | 'review' | 'denied', source: 'project' | 'global' | 'default' | 'unknown' }
const decisions = ref(new Map<string, Decision>())
async function loadDecisions() {
  try {
    const res = await api<{ items: Decision[] }>(`/api/licenses/scans/${encodeURIComponent(props.scanId)}`)
    decisions.value = new Map(res.items.map(i => [i.purl, i]))
  }
  catch {
    decisions.value = new Map()
  }
}

watch(page, () => void load())
watch(() => props.scanId, () => {
  void load()
  void loadDecisions()
})
onMounted(() => {
  void load()
  void loadDecisions()
})
onBeforeUnmount(() => clearTimeout(debounce))

const ecosystemItems = computed(() => [
  { label: t('sbom.filters.allEcosystems'), value: 'all' },
  ...(data.value?.ecosystems ?? []).map(e => ({ label: `${e.ecosystem} (${e.count})`, value: e.ecosystem })),
])
const licenseItems = computed(() => [
  { label: t('sbom.filters.allLicenses'), value: 'all' },
  ...(data.value?.licenses ?? []).map(l => ({ label: `${l.license} (${l.count})`, value: l.license })),
])
const directItems = computed(() => [
  { label: t('sbom.filters.allDeps'), value: 'all' },
  { label: t('sbom.filters.direct'), value: 'true' },
  { label: t('sbom.filters.indirect'), value: 'false' },
])
const sortItems = computed(() => SORTS.map(s => ({ label: t(`sbom.sort.${s}`), value: s })))

function directText(d: boolean | null): string {
  return d === null ? t('sbom.directUnknown') : d ? t('sbom.directYes') : t('sbom.directNo')
}

const columns = computed<TableColumn<Component>[]>(() => [
  {
    accessorKey: 'name',
    header: t('sbom.columns.name'),
    cell: ({ row }) => h('div', { class: 'min-w-0' }, [
      h('div', { class: 'font-medium break-all' }, row.original.name),
      h('div', { class: 'font-mono text-xs text-muted break-all' }, row.original.purl),
    ]),
  },
  { accessorKey: 'version', header: t('sbom.columns.version'), cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.version ?? '—') },
  { accessorKey: 'ecosystem', header: t('sbom.columns.ecosystem') },
  {
    id: 'licenses',
    header: t('sbom.columns.licenses'),
    cell: ({ row }) => {
      const d = decisions.value.get(row.original.purl)
      if (d) return h(SbomLicenseDecision, { licenses: row.original.licenses, decision: d.decision, source: d.source })
      return row.original.licenses.length
        ? h('span', { class: 'text-xs' }, row.original.licenses.join(', '))
        : h('span', { class: 'text-xs text-muted' }, t('sbom.noLicense'))
    },
  },
  { id: 'direct', header: t('sbom.columns.direct'), cell: ({ row }) => h('span', { class: 'text-xs' }, directText(row.original.direct)) },
  { id: 'paths', header: t('sbom.columns.paths'), cell: ({ row }) => h('span', { class: 'font-mono text-xs break-all text-muted' }, row.original.paths.join(', ')) },
])

const ignored = computed(() => (data.value?.coverage?.ignored_no_purl ?? 0) + (data.value?.coverage?.ignored_invalid_purl ?? 0))
const exportUrl = computed(() => `/api/scans/${encodeURIComponent(props.scanId)}/sbom/export`)
</script>

<template>
  <UCard data-testid="scan-sbom">
    <template #header>
      <div class="flex flex-wrap items-center gap-3">
        <div class="min-w-0">
          <h2 class="font-semibold">
            {{ t('sbom.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('sbom.help') }}
          </p>
        </div>
        <div class="ml-auto flex flex-wrap gap-2">
          <UButton
            v-if="data?.dtrack?.url"
            :to="data.dtrack.url"
            target="_blank"
            rel="noopener noreferrer"
            external
            size="sm"
            color="neutral"
            variant="outline"
            icon="i-lucide-external-link"
            :label="t('sbom.dtrack')"
            data-testid="sbom-dtrack"
          />
          <UButton
            v-if="data && data.total > 0"
            :to="exportUrl"
            external
            download
            size="sm"
            color="neutral"
            variant="outline"
            icon="i-lucide-download"
            :label="t('sbom.export')"
            data-testid="sbom-export"
          />
        </div>
      </div>
    </template>

    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-alert"
      :title="error"
      class="mb-3"
    />

    <div
      v-if="!data && loading"
      class="flex items-center gap-2 text-sm text-muted"
      data-testid="sbom-loading"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('sbom.loading') }}
    </div>

    <p
      v-else-if="data && data.total === 0"
      class="text-sm text-muted"
      data-testid="sbom-empty"
    >
      {{ t('sbom.none') }}
    </p>

    <template v-else-if="data">
      <p class="mb-3 text-sm text-muted">
        {{ t('sbom.summary', { total: data.total, ecosystems: data.ecosystems.length }) }}
        <template v-if="ignored">
          {{ t('sbom.ignored', { count: ignored }) }}
        </template>
        <template v-if="data.coverage && data.coverage.direct_known === false">
          {{ t('sbom.directNotKnown') }}
        </template>
        <template v-if="data.dtrack && !data.dtrack.url">
          {{ t('sbom.dtrackNoRoute') }}
        </template>
      </p>
      <div class="mb-3 flex flex-wrap items-center gap-2">
        <UInput
          v-model="filters.q"
          icon="i-lucide-search"
          :placeholder="t('sbom.filters.search')"
          class="w-56"
          data-testid="sbom-search"
        />
        <USelect
          v-model="filters.ecosystem"
          :items="ecosystemItems"
          class="w-40"
        />
        <USelect
          v-model="filters.license"
          :items="licenseItems"
          class="w-48"
        />
        <USelect
          v-model="filters.direct"
          :items="directItems"
          class="w-40"
        />
        <USelect
          v-model="filters.sort"
          :items="sortItems"
          class="w-36"
          :aria-label="t('sbom.sort.label')"
        />
        <UButton
          color="neutral"
          variant="ghost"
          size="sm"
          :icon="filters.order === 'asc' ? 'i-lucide-arrow-up-narrow-wide' : 'i-lucide-arrow-down-wide-narrow'"
          :aria-label="filters.order === 'asc' ? t('sbom.sort.asc') : t('sbom.sort.desc')"
          data-testid="sbom-order"
          @click="filters.order = filters.order === 'asc' ? 'desc' : 'asc'"
        />
      </div>
      <UTable
        :data="data.components"
        :columns="columns"
        :loading="loading"
        :empty="t('sbom.noMatch')"
      />
      <div
        v-if="data.matched > PER_PAGE"
        class="mt-3 flex justify-end"
      >
        <UPagination
          v-model:page="page"
          :total="data.matched"
          :items-per-page="PER_PAGE"
        />
      </div>
    </template>
  </UCard>
</template>
