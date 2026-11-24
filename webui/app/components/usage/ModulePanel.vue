<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Onglet « Consommation » du détail d'un module installé (F14) : statistiques
des analyses pour un scanner, courbes mémoire, CPU et disque sur 7 et 30 jours
pour un module permanent. Un module inutilisé depuis N jours est signalé avec
une suggestion de retrait : le bouton ouvre la modale de désinstallation
existante, jamais de retrait automatique. Un module requis par un autre n'est
jamais signalé (G1).
-->

<script setup lang="ts">
import type { ModuleUsageDetail, SeriesPoint } from '~/composables/useUsage'

const props = defineProps<{ moduleId: string, canUninstall?: boolean, names?: Record<string, string> }>()
const emit = defineEmits<{ uninstall: [] }>()

const { t } = useI18n()
const { api, errorMessage } = useApi()
const fmt = useFormat()
const u = useUsageFormat()

const detail = ref<ModuleUsageDetail | null>(null)
const loading = ref(false)
const error = ref('')
async function load() {
  loading.value = true
  try {
    detail.value = await api<ModuleUsageDetail>(`/api/usage/modules/${encodeURIComponent(props.moduleId)}`)
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
watch(() => props.moduleId, load)
defineExpose({ load })

const usage = computed(() => detail.value?.usage ?? null)
const period = ref<'7' | '30'>('7')
const periods = computed(() => [{ label: t('usage.period7'), value: '7' }, { label: t('usage.period30'), value: '30' }])
const series = computed<SeriesPoint[]>(() => detail.value?.series?.[period.value === '7' ? 7 : 30] ?? [])
const periodLabel = computed(() => (period.value === '7' ? t('usage.period7') : t('usage.period30')))
const charts = computed(() => [
  { key: 'memory', label: t('usage.memory'), points: series.value.map(p => ({ at: p.at, value: p.memory_avg_mb })), format: u.mb },
  { key: 'cpu', label: t('usage.cpu'), points: series.value.map(p => ({ at: p.at, value: p.cpu_avg_pct })), format: u.pct },
  { key: 'disk', label: t('usage.disk'), points: series.value.map(p => ({ at: p.at, value: p.disk_mb })), format: u.mb },
])
const requiredBy = computed(() => (usage.value?.required_by ?? []).map(id => props.names?.[id] ?? id).join(', '))
const stats = computed(() => {
  const s = usage.value?.scanner
  if (!s) return []
  return [
    { label: t('usage.runs'), value: String(s.runs) },
    { label: t('usage.failures'), value: String(s.failures) },
    { label: t('usage.memoryMax'), value: u.mb(s.memory_max_mb) },
    { label: t('usage.memoryMedian'), value: u.mb(s.memory_median_mb) },
    { label: t('usage.cpuAvg'), value: s.cpu_avg_ms === null ? t('usage.notMeasured') : u.ms(s.cpu_avg_ms) },
    { label: t('usage.durationAvg'), value: u.ms(s.duration_avg_ms) },
    { label: t('usage.durationP95'), value: u.ms(s.duration_p95_ms) },
    { label: t('usage.lastUsed'), value: fmt.date(usage.value?.last_used_at) },
  ]
})
const serviceStats = computed(() => {
  const s = usage.value?.service
  if (!s) return []
  return [
    { label: t('usage.current'), value: s.latest ? `${u.mb(s.latest.memory_mb)} · ${u.pct(s.latest.cpu_pct)} · ${u.mb(s.latest.disk_mb)}` : '—' },
    { label: t('usage.average'), value: `${u.mb(s.memory_avg_mb)} · ${u.pct(s.cpu_avg_pct)}` },
    { label: t('usage.peak'), value: `${u.mb(s.memory_max_mb)} · ${u.mb(s.disk_max_mb)}` },
  ]
})
</script>

<template>
  <UCard>
    <template #header>
      <div class="flex items-start justify-between gap-2">
        <div>
          <h2 class="font-semibold">
            {{ t('usage.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('usage.help') }}
          </p>
        </div>
        <UButton
          icon="i-lucide-refresh-cw"
          color="neutral"
          variant="ghost"
          :loading="loading"
          :aria-label="t('common.refresh')"
          @click="load()"
        />
      </div>
    </template>

    <div
      v-if="loading && !detail"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
      aria-live="polite"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      <span>{{ t('app.loading') }}</span>
    </div>
    <UAlert
      v-else-if="error"
      color="error"
      variant="subtle"
      :title="error"
    />
    <div
      v-else-if="usage"
      class="space-y-4"
    >
      <UAlert
        v-if="usage.unused && detail"
        color="warning"
        variant="subtle"
        icon="i-lucide-package-x"
        :title="t('usage.unused.title', { days: detail.unused_days })"
        :description="`${usage.unused_reason === 'no-scan' ? t('usage.unused.noScan', { days: detail.unused_days }) : t('usage.unused.noDependent')} ${t('usage.unused.suggest')}`"
        :actions="canUninstall ? [{ label: t('usage.unused.uninstall'), color: 'warning', variant: 'outline', onClick: () => emit('uninstall') }] : undefined"
      />
      <p
        v-if="usage.required_by.length"
        class="text-sm text-muted"
      >
        {{ t('usage.requiredBy', { list: requiredBy }) }}
      </p>
      <p
        v-else-if="!usage.judged"
        class="text-sm text-muted"
      >
        {{ t('usage.notJudged') }}
      </p>

      <template v-if="usage.scanner">
        <p
          v-if="usage.scanner.runs === 0"
          class="text-sm text-muted"
        >
          {{ t('usage.noRuns') }}
        </p>
        <dl class="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <div
            v-for="s in stats"
            :key="s.label"
          >
            <dt class="text-muted">
              {{ s.label }}
            </dt>
            <dd class="font-medium">
              {{ s.value }}
            </dd>
          </div>
        </dl>
      </template>

      <template v-else>
        <dl class="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-3">
          <div
            v-for="s in serviceStats"
            :key="s.label"
          >
            <dt class="text-muted">
              {{ s.label }}
            </dt>
            <dd class="font-medium">
              {{ s.value }}
            </dd>
          </div>
        </dl>
        <p
          v-if="!series.length"
          class="text-sm text-muted"
        >
          {{ t('usage.noSamples') }}
        </p>
        <template v-else>
          <UTabs
            v-model="period"
            :items="periods"
            :content="false"
            size="xs"
          />
          <div class="grid grid-cols-1 gap-4 md:grid-cols-3">
            <UsageChart
              v-for="c in charts"
              :key="c.key"
              :points="c.points"
              :label="t('usage.chartLabel', { metric: c.label, period: periodLabel })"
              :format="c.format"
            />
          </div>
        </template>
      </template>
    </div>
  </UCard>
</template>
