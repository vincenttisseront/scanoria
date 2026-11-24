<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

H3 (0.5) : badge « KEV » (vulnérabilité exploitée activement, catalogue de la
CISA) et probabilité d'exploitation EPSS (pourcentage et percentile) d'un
résultat. Rien pour un résultat sans CVE connue des bases.
-->

<script setup lang="ts">
const props = defineProps<{
  epss: number | null | undefined
  epssPercentile: number | null | undefined
  kev: boolean | null | undefined
  kevAdded?: string | null
}>()
const { t, locale } = useI18n()

function percent(v: number): string {
  const pct = v * 100
  return new Intl.NumberFormat(locale.value, { maximumFractionDigits: pct < 1 ? 2 : 1 }).format(pct) + ' %'
}
const epssText = computed(() => (typeof props.epss === 'number'
  ? t('intel.epssValue', { pct: percent(props.epss), percentile: typeof props.epssPercentile === 'number' ? percent(props.epssPercentile) : t('intel.none') })
  : null))
const epssColor = computed(() => (typeof props.epss !== 'number' ? 'neutral' : props.epss >= 0.1 ? 'error' : props.epss >= 0.01 ? 'warning' : 'neutral'))
const kevTitle = computed(() => (props.kevAdded ? t('intel.kevHelp', { date: props.kevAdded }) : t('intel.kevHelpNoDate')))
</script>

<template>
  <div
    v-if="kev || epssText"
    class="flex flex-wrap items-center gap-1"
    data-testid="intel-badges"
  >
    <UBadge
      v-if="kev"
      color="error"
      variant="solid"
      icon="i-lucide-flame"
      :label="t('intel.kev')"
      :title="kevTitle"
      data-testid="kev-badge"
    />
    <UBadge
      v-if="epssText"
      :color="epssColor"
      variant="outline"
      :label="epssText"
      :title="t('intel.epssHelp')"
      data-testid="epss-badge"
    />
  </div>
  <span
    v-else
    class="text-muted"
  >{{ t('intel.none') }}</span>
</template>
