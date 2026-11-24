<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Sorties IA d'un résultat dans le panneau de détail : pré-tri suggéré à côté
du statut « nouveau » (I3), explication (I2) et traduction de la règle
(I17). Sans connecteur IA, rien n'est affiché et rien d'autre ne change
(CLAUDE.md § 3.5). Aucune de ces sorties ne modifie le statut du résultat.
-->

<script setup lang="ts">
defineProps<{
  findingId: string
  projectId: string
  status?: string
  title?: string
  secret?: boolean
}>()
</script>

<template>
  <div
    data-slot="finding-ai"
    class="space-y-3"
  >
    <AiTriage
      v-if="status === 'new'"
      :finding-id="findingId"
    />
    <AiExplanation
      kind="explain-finding"
      :subject-id="findingId"
    />
    <AiRuleTranslation
      v-if="!secret && title"
      :finding-id="findingId"
      :original="title"
    />
  </div>
</template>
