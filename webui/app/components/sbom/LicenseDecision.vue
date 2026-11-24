<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Décision de licence d'un composant (F8) : licences du SBOM et décision de
la politique (autorisée, à revoir, interdite), avec son origine. Prévu pour
la colonne « licence » de l'onglet SBOM d'une analyse (données de
GET /api/licenses/scans/:id).
-->

<script setup lang="ts">
const props = defineProps<{
  licenses: string[]
  decision: 'allowed' | 'review' | 'denied'
  source?: 'project' | 'global' | 'default' | 'unknown'
}>()

const { t } = useI18n()
const color = computed(() => ({ allowed: 'success', review: 'warning', denied: 'error' } as const)[props.decision])
const title = computed(() => props.source ? t(`licenses.source.${props.source}`) : undefined)
</script>

<template>
  <span class="inline-flex flex-wrap items-center gap-1">
    <span class="font-mono text-xs">{{ licenses.length ? licenses.join(', ') : t('licenses.none') }}</span>
    <UBadge
      :color="color"
      variant="subtle"
      size="sm"
      :title="title"
      :data-testid="`license-${decision}`"
    >
      {{ t(`licenses.decision.${decision}`) }}
    </UBadge>
  </span>
</template>
