<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Explication IA d'un résultat (I2) dans le panneau de détail. Sans connecteur
IA, elle ne montre rien et rien d'autre ne change (CLAUDE.md § 3.5). Le
projet sert seulement au cloisonnement côté serveur.
-->

<script setup lang="ts">
defineProps<{ findingId: string, projectId: string }>()
</script>

<template>
  <div data-slot="finding-ai">
    <AiExplanation
      kind="explain-finding"
      :subject-id="findingId"
    />
  </div>
</template>
