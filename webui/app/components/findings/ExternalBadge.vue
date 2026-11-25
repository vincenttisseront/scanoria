<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

J6 (0.6) : résultat externe (téléversé en SARIF ou CycloneDX), avec sa source
(outil, version, format). Rien pour un résultat d'un module de l'appliance.
-->

<script setup lang="ts">
const props = defineProps<{
  origin: string | null | undefined
  source?: { tool: string, version: string | null, format: string, uploaded_via?: string } | null
}>()
const { t } = useI18n()
const label = computed(() => {
  const s = props.source
  if (!s) return t('external.badge')
  return `${t('external.badge')} · ${s.tool}${s.version ? ` ${s.version}` : ''}`
})
const help = computed(() => {
  const s = props.source
  return s
    ? t('external.badgeHelp', { tool: s.tool, version: s.version ?? '?', format: s.format === 'cyclonedx' ? 'CycloneDX' : 'SARIF' })
    : t('external.badgeHelpShort')
})
</script>

<template>
  <UBadge
    v-if="origin === 'external'"
    color="neutral"
    variant="outline"
    icon="i-lucide-upload"
    :label="label"
    :title="help"
    data-testid="external-badge"
  />
</template>
