<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Emplacement réservé à l'explication IA d'un résultat (I2, chantier F de la
0.3) dans le panneau de détail. Sans connecteur IA, il ne montre rien et rien
d'autre ne change (CLAUDE.md § 3.5). Le chantier F remplace ce corps en
gardant ses propriétés.
-->

<script setup lang="ts">
defineProps<{ findingId: string, projectId: string }>()
</script>

<template>
  <div
    data-slot="finding-ai"
    class="hidden"
  />
</template>
