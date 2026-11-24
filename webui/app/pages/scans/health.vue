<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Santé des analyses (G20) : par outil, sur 7 ou 30 jours, exécutions, taux
d'échec par classe (infrastructure, outil, entrée), délais dépassés, mémoire
épuisée, sorties invalides et durées. Puis les analyses en échec récentes,
avec un lien vers chacune et, pour les opérateurs, le journal complet masqué
de chaque module en échec. Tout est calculé sans réglage.
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'
import type { FailedScan, ScanHealth, ToolHealth } from '~/composables/useUsage'

const { t } = useI18n()
useHead({ title: computed(() => t('health.title')) })

const session = useSession()
const canDownload = computed(() => session.can('operator'))
const { api, errorMessage } = useApi()
const { label } = useScanText()
const fmt = useFormat()
const u = useUsageFormat()

const data = ref<ScanHealth | null>(null)
const loading = ref(false)
const error = ref('')
async function load() {
  loading.value = true
  try {
    data.value = await api<ScanHealth>('/api/health/scans')
    error.value = ''
  }
  catch (err) {
    error.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const windowDays = ref<'7' | '30'>('7')
const windows = computed(() => [7, 30].map(d => ({ label: t('health.window', { days: d }), value: String(d) })))
const tools = computed<ToolHealth[]>(() => data.value?.windows[windowDays.value === '7' ? 7 : 30] ?? [])

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')
const rateColor = (r: number) => (r >= 0.2 ? 'error' : r > 0 ? 'warning' : 'success')
const toolColumns = computed<TableColumn<ToolHealth>[]>(() => [
  { id: 'tool', header: t('health.tool'), cell: ({ row }) => h('span', { class: 'font-medium' }, row.original.module_id) },
  { id: 'runs', header: t('health.runs'), cell: ({ row }) => String(row.original.runs) },
  {
    id: 'rate',
    header: t('health.failureRate'),
    cell: ({ row }) => h(UBadge, { color: rateColor(row.original.failure_rate), variant: 'subtle', label: u.rate(row.original.failure_rate) }),
  },
  { id: 'infra', header: label('errorClass', 'infra'), cell: ({ row }) => String(row.original.by_class.infra) },
  { id: 'toolClass', header: label('errorClass', 'tool'), cell: ({ row }) => String(row.original.by_class.tool) },
  { id: 'input', header: label('errorClass', 'input'), cell: ({ row }) => String(row.original.by_class.input) },
  { id: 'timeouts', header: t('health.timeouts'), cell: ({ row }) => String(row.original.timeouts) },
  { id: 'oom', header: t('health.oom'), cell: ({ row }) => String(row.original.oom) },
  { id: 'invalid', header: t('health.invalidOutput'), cell: ({ row }) => String(row.original.invalid_output) },
  { id: 'avg', header: t('health.durationAvg'), cell: ({ row }) => u.ms(row.original.duration_avg_ms) },
  { id: 'p95', header: t('health.durationP95'), cell: ({ row }) => u.ms(row.original.duration_p95_ms) },
  { id: 'last', header: t('health.lastFailure'), cell: ({ row }) => (row.original.last_failure_at ? fmt.date(row.original.last_failure_at) : '—') },
])

const failureColumns = computed<TableColumn<FailedScan>[]>(() => [
  {
    id: 'scan',
    header: t('health.failures.scan'),
    cell: ({ row }) => h(ULink, { to: `/scans/${row.original.id}`, class: 'font-medium text-primary' }, () => `${row.original.project_name} #${row.original.number}`),
  },
  {
    id: 'modules',
    header: t('health.failures.modules'),
    cell: ({ row }) => h('ul', { class: 'space-y-1' }, row.original.modules.map(m => h('li', { class: 'flex flex-wrap items-center gap-2' }, [
      h('span', { class: 'font-mono text-xs' }, m.module_id),
      h(UBadge, { color: 'error', variant: 'subtle', size: 'sm', label: label('moduleStatus', m.status) }),
      m.error_class ? h('span', { class: 'text-xs text-muted' }, label('errorClass', m.error_class)) : null,
      m.has_log && canDownload.value
        ? h('a', {
            href: `/api/scans/${row.original.id}/modules/${m.module_id}/log`,
            download: '',
            class: 'text-xs text-primary underline',
            title: t('health.failures.logHelp'),
          }, t('health.failures.log'))
        : null,
    ]))),
  },
  { id: 'finished', header: t('health.failures.finished'), cell: ({ row }) => fmt.date(row.original.finished_at) },
])
</script>

<template>
  <PageShell :title="t('health.title')">
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

    <p class="text-sm text-muted">
      {{ t('health.help') }} {{ t('health.classHelp') }}
    </p>

    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      :title="error"
    />

    <UCard>
      <UTabs
        v-model="windowDays"
        :items="windows"
        :content="false"
        class="mb-3"
      />
      <UTable
        :data="tools"
        :columns="toolColumns"
        :loading="loading"
        :empty="t('health.empty')"
      />
    </UCard>

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('health.failures.title') }}
        </h2>
      </template>
      <UTable
        :data="data?.recent_failures ?? []"
        :columns="failureColumns"
        :loading="loading"
        :empty="t('health.failures.empty')"
      />
    </UCard>
  </PageShell>
</template>
