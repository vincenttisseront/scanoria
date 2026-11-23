<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Indicateur d'attente d'une demande au service root (étape courante traduite).
-->

<script setup lang="ts">
defineProps<{ active: boolean, label: string }>()
</script>

<template>
  <div
    v-if="active"
    class="flex items-center gap-2 text-sm text-muted"
    role="status"
    aria-live="polite"
  >
    <UIcon
      name="i-lucide-loader-circle"
      class="size-4 animate-spin"
    />
    <span>{{ label }}</span>
  </div>
</template>
