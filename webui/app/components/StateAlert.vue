<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Alertes de l'état publié par le service root : état absent, illisible ou
périmé, et alerte permanente après l'échec d'un retour arrière de mise à jour
(update.alert, E_ROLLBACK_FAILED).
-->

<script setup lang="ts">
import type { StateResponse } from '~/composables/useApplianceState'

const props = defineProps<{ data: StateResponse | null }>()
const { t } = useI18n()
const fmt = useFormat()

const updateAlert = computed(() => props.data?.state?.update?.alert ?? null)
const updateAlertDescription = computed(() => {
  const a = updateAlert.value
  if (!a) return ''
  return t('state.updateAlertDetail', {
    date: fmt.date(a.at),
    version: a.version ?? '?',
    message: a.message,
  })
})

const description = computed(() => {
  const d = props.data
  if (!d || d.available) return ''
  if (d.reason === 'stale') return t('state.stale', { age: d.age_seconds ?? '?' })
  if (d.reason === 'invalid') return t('state.invalid')
  return t('state.missing')
})
</script>

<template>
  <UAlert
    v-if="data && !data.available"
    color="warning"
    variant="subtle"
    icon="i-lucide-triangle-alert"
    :title="t('state.unavailable')"
    :description="description"
  />
  <UAlert
    v-if="updateAlert"
    color="error"
    variant="subtle"
    icon="i-lucide-octagon-x"
    :title="t('state.updateAlert')"
    :description="updateAlertDescription"
  />
</template>
