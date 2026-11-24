<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Gravité normalisée d'un résultat (critical … info), traduite et colorée.
-->

<script setup lang="ts">
const props = defineProps<{ severity: string }>()
const { t, te } = useI18n()
const COLORS: Record<string, 'error' | 'warning' | 'info' | 'neutral'> = {
  critical: 'error', high: 'error', medium: 'warning', low: 'info', info: 'neutral',
}
const label = computed(() => (te(`findings.severity.${props.severity}`) ? t(`findings.severity.${props.severity}`) : props.severity))
</script>

<template>
  <UBadge
    :color="COLORS[severity] ?? 'neutral'"
    :variant="severity === 'critical' ? 'solid' : 'subtle'"
    :label="label"
  />
</template>
