<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Type probable d'un secret générique (I14), déduit du contexte seulement,
affiché dans la carte du suivi du secret (F7). Aucune action : l'état du
secret ne change que par un clic d'une personne.
-->

<script setup lang="ts">
defineProps<{ findingId: string }>()
const { t } = useI18n()
const list = (v: unknown) => (Array.isArray(v) ? v as string[] : [])
</script>

<template>
  <AiTaskPanel
    kind="classify-secret"
    :subject-id="findingId"
    :title="t('ai.secret.title')"
    icon="i-lucide-key-round"
    :askable="false"
    compact
  >
    <template #default="{ output }">
      <div
        class="space-y-1"
        data-testid="ai-secret-class"
      >
        <div class="flex flex-wrap items-center gap-2">
          <UBadge
            color="neutral"
            variant="subtle"
            :label="t(`ai.secret.classes.${String(output.class)}`)"
          />
          <span class="text-xs text-muted">{{ t(`ai.secret.confidence.${String(output.confidence)}`) }}</span>
        </div>
        <p>{{ output.summary }}</p>
        <ul class="list-disc ps-5 text-xs text-muted">
          <li
            v-for="(r, i) in list(output.reasons)"
            :key="i"
          >
            {{ r }}
          </li>
        </ul>
        <p class="text-xs text-muted">
          {{ t('ai.secret.help') }}
        </p>
      </div>
    </template>
  </AiTaskPanel>
</template>
