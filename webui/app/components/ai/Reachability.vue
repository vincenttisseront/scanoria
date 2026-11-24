<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Atteignabilité assistée d'une vulnérabilité de dépendance (I11) : avis
« appel probable / improbable / indéterminé » de l'IA, avec les emplacements
cités (imports et appels relevés sans exécution par reach-index). Affiché à
côté de la priorité ; il ne lève jamais un blocage et ne change ni la gravité
ni le statut. Rien n'apparaît tant qu'aucun avis n'existe (précalculé après
l'analyse, quand l'index existe).
-->

<script setup lang="ts">
defineProps<{ findingId: string }>()
const { t } = useI18n()
interface Cited { ref: number, kind: 'import' | 'call', path: string, line: number, symbol: string }
interface Reason { ref: number, explanation: string }
function list<T>(v: unknown): T[] {
  return Array.isArray(v) ? v as T[] : []
}
const COLOR: Record<string, 'error' | 'success' | 'neutral'> = { probable: 'error', improbable: 'success', indeterminate: 'neutral' }
</script>

<template>
  <AiTaskPanel
    kind="assess-reachability"
    :subject-id="findingId"
    :title="t('ai.reach.title')"
    icon="i-lucide-route"
    :askable="false"
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-reachability"
      >
        <UBadge
          :color="COLOR[String(output.reachability)] ?? 'neutral'"
          variant="subtle"
          :label="t(`ai.reach.verdicts.${String(output.reachability)}`)"
          data-testid="ai-reach-verdict"
        />
        <p>{{ output.summary }}</p>
        <p
          v-if="output.downgraded"
          class="text-xs text-muted"
        >
          {{ t('ai.reach.downgraded') }}
        </p>
        <ul class="list-disc ps-5 text-xs">
          <li
            v-for="(r, i) in list<Reason>(output.reasons)"
            :key="i"
          >
            {{ r.explanation }}
          </li>
        </ul>
        <div v-if="list<Cited>(output.cited).length">
          <p class="text-xs text-muted">
            {{ t('ai.reach.cited') }}
          </p>
          <ul class="font-mono text-xs">
            <li
              v-for="c in list<Cited>(output.cited)"
              :key="c.ref"
            >
              {{ c.path }}:{{ c.line }} · {{ t(`ai.reach.${c.kind}`) }} {{ c.symbol }}
            </li>
          </ul>
        </div>
        <p class="text-xs text-muted">
          {{ t('ai.reach.help') }}
        </p>
      </div>
    </template>
  </AiTaskPanel>
</template>
