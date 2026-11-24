<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

F16 (0.5) : « confirmé par N outils », quand un même problème est trouvé par
plusieurs outils (clé de recoupement partagée). Rien pour un résultat seul.
-->

<script setup lang="ts">
const props = defineProps<{ group: { confirmations: number, tools: string[] } | null | undefined }>()
const { t } = useI18n()
const show = computed(() => !!props.group && props.group.confirmations >= 2)
</script>

<template>
  <UBadge
    v-if="show"
    color="primary"
    variant="subtle"
    icon="i-lucide-layers"
    :label="t('intel.correlation.confirmed', { count: group!.confirmations })"
    :title="t('intel.correlation.confirmedHelp', { tools: group!.tools.join(', ') })"
    data-testid="correlation-badge"
  />
</template>
