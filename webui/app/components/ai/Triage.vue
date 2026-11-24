<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Pré-tri suggéré (I3) dans le panneau de détail d'un résultat, à côté du
statut « nouveau ». Suggestion seulement : ce composant n'appelle jamais
l'API de tri, et le statut ne change que par un clic d'une personne.
-->

<script setup lang="ts">
defineProps<{ findingId: string }>()
const { t } = useI18n()

interface Reason { kind: string, quote: string, explanation: string, cited?: boolean }
const color = (s: unknown) => s === 'likely-false-positive' ? 'success' : s === 'likely-true-positive' ? 'error' : 'warning'
const reasons = (o: Record<string, unknown>) => (Array.isArray(o.reasons) ? o.reasons as Reason[] : [])
</script>

<template>
  <AiTaskPanel
    kind="triage-finding"
    :subject-id="findingId"
    :title="t('ai.triage.title')"
    icon="i-lucide-scale"
    compact
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-triage"
      >
        <div class="flex flex-wrap items-center gap-2">
          <UBadge
            :color="color(output.suggestion)"
            variant="subtle"
            :label="t(`ai.triage.${String(output.suggestion)}`)"
            data-testid="ai-triage-suggestion"
          />
          <span class="text-xs text-muted">{{ t('ai.triage.help') }}</span>
        </div>
        <p>{{ output.summary }}</p>
        <p
          v-if="output.downgraded"
          class="text-xs text-muted"
        >
          {{ t('ai.triage.downgraded') }}
        </p>
        <ul class="list-disc space-y-1 ps-5">
          <li
            v-for="(r, i) in reasons(output)"
            :key="i"
          >
            <span class="font-medium">{{ t(`ai.triage.reasons.${r.kind}`) }}</span> : {{ r.explanation }}
            <span
              v-if="r.cited && r.quote"
              class="block text-xs text-muted"
            >{{ t('ai.triage.quote') }} : <code>{{ r.quote }}</code></span>
          </li>
        </ul>
      </div>
    </template>
  </AiTaskPanel>
</template>
