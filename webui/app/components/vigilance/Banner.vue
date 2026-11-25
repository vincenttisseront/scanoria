<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Bandeau de vigilance (F19, G14), sur le tableau de bord et Mises à jour :
« module X vulnérable, mise à jour disponible », et canaris en échec.
Rien n'est affiché s'il n'y a rien à signaler ou si la lecture échoue.
-->

<script setup lang="ts">
import { subjectName, type VigilanceSummary } from '~/utils/vigilance'

const { t } = useI18n()
const { api } = useApi()
const data = ref<VigilanceSummary | null>(null)

async function load() {
  try {
    data.value = await api<VigilanceSummary>('/api/vigilance')
  }
  catch {
    data.value = null
  }
}
onMounted(load)
defineExpose({ load })

const alerts = computed(() => data.value?.alerts ?? [])
const failing = computed(() => data.value?.canaries.failing ?? [])
const link = (subject: string) => (subject === 'console' ? '/updates' : `/catalog/${encodeURIComponent(subjectName(subject))}`)
</script>

<template>
  <div
    v-if="alerts.length || failing.length"
    class="space-y-2"
  >
    <UAlert
      v-if="alerts.length"
      :color="alerts.some(a => a.critical > 0) ? 'error' : 'warning'"
      variant="subtle"
      icon="i-lucide-shield-alert"
      :title="t('vigilance.banner.vulnTitle', { count: alerts.length })"
      data-testid="vigilance-vuln-banner"
    >
      <template #description>
        <ul class="space-y-0.5">
          <li
            v-for="a in alerts"
            :key="a.subject"
          >
            <NuxtLink
              :to="link(a.subject)"
              class="font-medium underline"
            >
              {{ a.subject === 'console' ? t('vigilance.console') : subjectName(a.subject) }}
            </NuxtLink>
            : {{ t('vigilance.banner.vulnLine', { total: a.total, critical: a.critical, high: a.high, version: a.update_available }) }}
          </li>
        </ul>
      </template>
    </UAlert>
    <UAlert
      v-if="failing.length"
      color="warning"
      variant="subtle"
      icon="i-lucide-bird"
      :title="t('vigilance.banner.canaryTitle', { count: failing.length })"
      data-testid="vigilance-canary-banner"
    >
      <template #description>
        <p class="mb-1">
          {{ t('vigilance.banner.canaryHelp') }}
        </p>
        <span
          v-for="(id, i) in failing"
          :key="id"
        >
          <NuxtLink
            :to="`/catalog/${encodeURIComponent(id)}`"
            class="font-medium underline"
          >{{ id }}</NuxtLink><span v-if="i < failing.length - 1">, </span>
        </span>
      </template>
    </UAlert>
  </div>
</template>
