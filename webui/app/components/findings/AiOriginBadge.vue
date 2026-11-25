<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

0.7 (contrat 32) : résultat d'un module d'analyse par IA. Badge « IA » :
informatif, hors verdict tant qu'une personne ne l'a pas confirmé. Rien pour
un résultat d'un autre module ou d'un outil externe.
-->

<script setup lang="ts">
const props = defineProps<{
  origin: string | null | undefined
  /** Absent : état inconnu (liste) ; vrai : confirmé, il compte dans le verdict. */
  confirmed?: boolean | null
}>()
const { t } = useI18n()
const help = computed(() => (props.confirmed ? t('aiFindings.badgeConfirmedHelp') : t('aiFindings.badgeHelp')))
</script>

<template>
  <UBadge
    v-if="origin === 'ai'"
    :color="confirmed ? 'primary' : 'neutral'"
    variant="subtle"
    icon="i-lucide-sparkles"
    :label="confirmed ? t('aiFindings.badgeConfirmed') : t('aiFindings.badge')"
    :title="help"
    data-testid="ai-origin-badge"
  />
</template>
