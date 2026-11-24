<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Bandeau du tableau de bord (F3, contrat 16) : projets nouvellement touchés
par une re-corrélation depuis 7 jours (critique, élevé, KEV ou malveillant).
Rien n'est affiché s'il n'y en a pas ou si la lecture échoue.
-->

<script setup lang="ts">
interface Exposure {
  project: { id: string, slug: string, name: string }
  at: string
  scan_id: string | null
  count: number
  malicious: number
  kev: number
  critical: number
  high: number
}

const { t } = useI18n()
const { api } = useApi()
const fmt = useFormat()
const items = ref<Exposure[]>([])

async function load() {
  try {
    items.value = (await api<{ items: Exposure[] }>('/api/components/exposures')).items
  }
  catch {
    items.value = []
  }
}
onMounted(load)
defineExpose({ load })

const malicious = computed(() => items.value.some(i => i.malicious > 0))
</script>

<template>
  <UAlert
    v-if="items.length"
    :color="malicious ? 'error' : 'warning'"
    variant="subtle"
    icon="i-lucide-radar"
    :title="t('components.exposures.title', { count: items.length })"
    data-testid="exposure-banner"
  >
    <template #description>
      <p class="mb-1">
        {{ t('components.exposures.help') }}
      </p>
      <ul class="space-y-0.5">
        <li
          v-for="i in items.slice(0, 8)"
          :key="i.project.id"
        >
          <NuxtLink
            :to="i.scan_id ? `/scans/${i.scan_id}` : `/projects/${i.project.id}`"
            class="font-medium underline"
          >
            {{ i.project.name }}
          </NuxtLink>
          :
          <span v-if="i.malicious">{{ t('components.exposures.malicious', { n: i.malicious }) }} · </span>
          <span v-if="i.kev">{{ t('components.exposures.kev', { n: i.kev }) }} · </span>
          {{ t('components.exposures.counts', { critical: i.critical, high: i.high }) }}
          <span class="text-muted">({{ fmt.date(i.at) }})</span>
        </li>
      </ul>
    </template>
  </UAlert>
</template>
