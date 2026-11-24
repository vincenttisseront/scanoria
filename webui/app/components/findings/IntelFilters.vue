<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Filtres de la 0.5 dans les Résultats : EPSS minimal, KEV seulement (H3) et
regroupement des résultats recoupés entre outils (F16, actif par défaut).
Affiche aussi la date des bases EPSS et KEV importées, ou comment les obtenir.
-->

<script setup lang="ts">
const epssMin = defineModel<string>('epssMin', { default: 'all' })
const kev = defineModel<boolean>('kev', { default: false })
const grouped = defineModel<boolean>('grouped', { default: true })
const { t } = useI18n()
const { api } = useApi()
const fmt = useFormat()

const THRESHOLDS = ['0.01', '0.1', '0.5'] as const
const epssItems = computed(() => [
  { label: t('intel.filters.epssAll'), value: 'all' },
  ...THRESHOLDS.map(v => ({ label: t('intel.filters.epssFrom', { pct: `${Number(v) * 100} %` }), value: v })),
])

interface FeedStatus { id: string, rows: number | null, imported_at: string | null, source_updated_at: string | null }
const feeds = ref<FeedStatus[] | null>(null)
onMounted(async () => {
  try {
    feeds.value = (await api<{ feeds: FeedStatus[] }>('/api/intel/status')).feeds
  }
  catch {
    feeds.value = null
  }
})
const imported = computed(() => (feeds.value ?? []).filter(f => f.imported_at))
const oldest = computed(() => imported.value.map(f => f.source_updated_at ?? f.imported_at!).sort()[0] ?? null)
</script>

<template>
  <div class="flex flex-wrap items-center gap-4">
    <UFormField :label="t('intel.filters.epss')">
      <USelect
        v-model="epssMin"
        :items="epssItems"
        class="w-32"
        data-testid="filter-epss"
      />
    </UFormField>
    <UCheckbox
      v-model="kev"
      :label="t('intel.filters.kev')"
      data-testid="filter-kev"
    />
    <UCheckbox
      v-model="grouped"
      :label="t('intel.filters.grouped')"
      :title="t('intel.filters.groupedHelp')"
      data-testid="filter-grouped"
    />
    <span
      v-if="feeds && imported.length"
      class="text-xs text-muted"
      :title="t('intel.sortHelp')"
      data-testid="intel-status"
    >{{ t('intel.status', { date: fmt.date(oldest) }) }}</span>
    <span
      v-else-if="feeds"
      class="text-xs text-muted"
      data-testid="intel-status-missing"
    >{{ t('intel.statusMissing') }}</span>
  </div>
</template>
