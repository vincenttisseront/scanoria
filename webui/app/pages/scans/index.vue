<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Analyses : file en direct (dans l'ordre où le worker la prendra, G17,
rafraîchie toutes les 3 s) et historique filtrable. Un clic ouvre le détail.
-->

<script setup lang="ts">
import type { TableColumn, TableRow } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'

const { t } = useI18n()
useHead({ title: computed(() => t('scans.title')) })

const { api } = useApi()
const { label, scanError } = useScanText()
const fmt = useFormat()
const toast = useToast()

const PAGE = 50
const tab = ref<'queue' | 'history'>('queue')
const page = ref(1)
const filters = reactive({ status: 'all', verdict: 'all', trigger: 'all' })
const items = ref<ScanSummary[]>([])
const total = ref(0)
const loading = ref(false)

async function load(quiet = false) {
  if (!quiet) loading.value = true
  try {
    const query: Record<string, unknown> = tab.value === 'queue'
      ? { status: 'active', limit: 200 }
      : { limit: PAGE, offset: (page.value - 1) * PAGE }
    if (tab.value === 'history') {
      if (filters.status !== 'all') query.status = filters.status
      if (filters.verdict !== 'all') query.verdict = filters.verdict
      if (filters.trigger !== 'all') query.trigger = filters.trigger
    }
    const res = await api<{ items: ScanSummary[], total: number }>('/api/scans', { query })
    items.value = res.items
    total.value = res.total
  }
  catch (err) {
    if (!quiet) toast.add({ title: scanError(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}

let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void load()
  timer = setInterval(() => {
    if (tab.value === 'queue') void load(true)
  }, 3000)
})
onBeforeUnmount(() => clearInterval(timer))
watch(tab, () => {
  page.value = 1
  void load()
})
watch(page, () => load())
watch(filters, () => {
  if (page.value !== 1) page.value = 1
  else void load()
})

const all = computed(() => ({ label: t('scans.filters.all'), value: 'all' }))
const statusItems = computed(() => [all.value, ...['queued', 'dispatched', 'running', 'ingesting', 'done', 'error', 'cancelled']
  .map(s => ({ label: label('statuses', s), value: s }))])
const verdictItems = computed(() => [all.value, ...['passed', 'failed', 'inconclusive'].map(v => ({ label: label('verdicts', v), value: v }))])
const triggerItems = computed(() => [all.value, ...['manual', 'schedule', 'commit', 'webhook', 'api', 'release', 'replay']
  .map(v => ({ label: label('triggers', v), value: v }))])

const UBadge = resolveComponent('UBadge')
const columns = computed<TableColumn<ScanSummary>[]>(() => [
  {
    id: 'project',
    header: t('scans.project'),
    cell: ({ row }) => h('span', {}, [h('span', { class: 'font-medium' }, row.original.project_name), h('span', { class: 'text-muted' }, ` #${row.original.number}`)]),
  },
  { id: 'ref', header: t('scans.ref'), cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.commit_sha ? `${row.original.ref} @ ${row.original.commit_sha.slice(0, 10)}` : row.original.ref) },
  { id: 'trigger', header: t('scans.trigger'), cell: ({ row }) => label('triggers', row.original.trigger) },
  { id: 'profile', header: t('scans.profile'), cell: ({ row }) => row.original.profile },
  {
    id: 'priority',
    header: t('scans.priority'),
    cell: ({ row }) => (row.original.effective_priority !== row.original.priority && row.original.status === 'queued'
      ? `${row.original.priority} → ${row.original.effective_priority}`
      : String(row.original.priority)),
  },
  {
    id: 'status',
    header: t('scans.status'),
    cell: ({ row }) => h(UBadge, { color: scanStatusColor(row.original.status), variant: 'subtle', label: label('statuses', row.original.status) }),
  },
  {
    id: 'verdict',
    header: t('scans.verdict'),
    cell: ({ row }) => (row.original.verdict
      ? h(UBadge, { color: verdictColor(row.original.verdict), variant: 'subtle', label: label('verdicts', row.original.verdict) })
      : '—'),
  },
  { id: 'queued', header: t('scans.queuedAt'), cell: ({ row }) => fmt.date(row.original.queued_at) },
])

function onSelect(_e: Event, row: TableRow<ScanSummary>) {
  void navigateTo(`/scans/${row.original.id}`)
}

const tabs = computed(() => [
  { label: t('scans.tabs.queue'), value: 'queue', icon: 'i-lucide-list-ordered' },
  { label: t('scans.tabs.history'), value: 'history', icon: 'i-lucide-history' },
])
</script>

<template>
  <PageShell :title="t('scans.title')">
    <template #actions>
      <UButton
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="ghost"
        :loading="loading"
        :aria-label="t('common.refresh')"
        @click="load()"
      />
    </template>

    <UTabs
      v-model="tab"
      :items="tabs"
      :content="false"
    />

    <p
      v-if="tab === 'queue'"
      class="text-sm text-muted"
    >
      {{ t('scans.queueHelp') }}
    </p>
    <div
      v-else
      class="flex flex-wrap items-end gap-3"
    >
      <UFormField :label="t('scans.status')">
        <USelect
          v-model="filters.status"
          :items="statusItems"
          class="w-44"
        />
      </UFormField>
      <UFormField :label="t('scans.verdict')">
        <USelect
          v-model="filters.verdict"
          :items="verdictItems"
          class="w-44"
        />
      </UFormField>
      <UFormField :label="t('scans.trigger')">
        <USelect
          v-model="filters.trigger"
          :items="triggerItems"
          class="w-44"
        />
      </UFormField>
    </div>

    <UCard>
      <p class="mb-2 text-xs text-muted">
        {{ t('scans.total', { total }) }}
      </p>
      <UTable
        :data="items"
        :columns="columns"
        :loading="loading"
        :empty="tab === 'queue' ? t('scans.emptyQueue') : t('scans.empty')"
        class="cursor-pointer"
        @select="onSelect"
      />
      <div
        v-if="tab === 'history' && total > PAGE"
        class="mt-4 flex justify-end"
      >
        <UPagination
          v-model:page="page"
          :total="total"
          :items-per-page="PAGE"
        />
      </div>
    </UCard>
  </PageShell>
</template>
