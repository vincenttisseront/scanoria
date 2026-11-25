<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

I10 : motif d'exception et durée PROPOSÉS par l'IA pour un résultat, dans la
modale de demande. « Utiliser ce motif » recopie le texte dans le formulaire :
la personne le relit, le corrige et soumet elle-même ; rien n'est jamais
soumis automatiquement. Mention « proposé par IA », modèle et retour 👍/👎
(I24) par le cadre commun. Rien n'est affiché sans connecteur ni pour un
projet « aucun envoi à l'IA ».
-->

<script setup lang="ts">
defineProps<{ findingId: string }>()
const emit = defineEmits<{ use: [draft: { reason: string, days: number }] }>()
const { t } = useI18n()

function list(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}
function use(output: Record<string, unknown>) {
  const days = typeof output.expires_in_days === 'number' ? output.expires_in_days : 90
  emit('use', { reason: String(output.reason ?? ''), days })
}
</script>

<template>
  <AiTaskPanel
    kind="draft-exception"
    :subject-id="findingId"
    :title="t('triage.draft.title')"
    :ask-label="t('triage.draft.ask')"
    icon="i-lucide-pen-line"
    compact
  >
    <template #default="{ output }">
      <div
        class="space-y-2 text-sm"
        data-testid="ai-exception-draft"
      >
        <p class="whitespace-pre-wrap break-words">
          {{ output.reason }}
        </p>
        <p class="text-xs text-muted">
          {{ t('triage.draft.duration', { days: Number(output.expires_in_days) }) }} · {{ output.duration_rationale }}
        </p>
        <ul
          v-if="list(output.to_check).length"
          class="list-disc ps-5 text-xs"
        >
          <li
            v-for="(c, i) in list(output.to_check)"
            :key="i"
          >
            {{ c }}
          </li>
        </ul>
        <UButton
          size="xs"
          icon="i-lucide-clipboard-paste"
          :label="t('triage.draft.use')"
          data-testid="ai-exception-draft-use"
          @click="use(output)"
        />
      </div>
    </template>
  </AiTaskPanel>
</template>
