<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Résumé d'une analyse (I5), en tête de la page d'analyse : ce qui a changé,
les trois priorités (liens vers les résultats, construits par le serveur),
ce qui bloque, ce qui n'a pas été couvert (G15).
-->

<script setup lang="ts">
defineProps<{ scanId: string }>()
const { t } = useI18n()
interface Priority { ref: number, why: string, link?: string, severity?: string }
const priorities = (o: Record<string, unknown>) => (Array.isArray(o.priorities) ? o.priorities as Priority[] : [])
// Seuls les liens internes construits par le serveur sont suivis.
const safeLink = (l?: string) => (l && /^\/findings\?[A-Za-z0-9=&_-]+$/.test(l) ? l : null)
</script>

<template>
  <AiTaskPanel
    kind="summarize-scan"
    :subject-id="scanId"
    :title="t('ai.summary.title')"
    icon="i-lucide-notebook-text"
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-summary"
      >
        <p class="font-medium">
          {{ output.headline }}
        </p>
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.summary.changes') }}
          </h4>
          <p>{{ output.changes }}</p>
        </div>
        <div v-if="priorities(output).length">
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.summary.priorities') }}
          </h4>
          <ol class="list-decimal space-y-1 ps-5">
            <li
              v-for="p in priorities(output)"
              :key="p.ref"
            >
              <FindingsSeverityBadge
                v-if="p.severity"
                :severity="p.severity"
                class="me-1"
              />
              {{ p.why }}
              <NuxtLink
                v-if="safeLink(p.link)"
                :to="safeLink(p.link)!"
                class="ms-1 text-primary underline"
              >{{ t('ai.summary.open') }}</NuxtLink>
            </li>
          </ol>
        </div>
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.summary.blocking') }}
          </h4>
          <p>{{ output.blocking }}</p>
        </div>
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.summary.notCovered') }}
          </h4>
          <p>{{ output.not_covered }}</p>
        </div>
      </div>
    </template>
  </AiTaskPanel>
</template>
