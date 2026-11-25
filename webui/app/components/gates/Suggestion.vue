<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

I19 : seuils de quality gate proposés par l'IA pour un projet, à partir de
métadonnées de son historique seulement. La proposition passe d'elle-même
dans le simulateur F9 (origin « ai ») : son effet s'affiche ici
pour un opérateur. Les
exceptions candidates sont montrées, jamais créées. « Reprendre dans le
gate » ouvre la page du gate préremplie : un administrateur relit, simule et
enregistre lui-même (audité « proposé par IA »). Rien n'est affiché sans
connecteur ni pour un projet « aucun envoi à l'IA ».
-->

<script setup lang="ts">
import type { SimulationRow } from '~/composables/useGateSimulation'

const props = defineProps<{ projectId: string }>()
const { t, te } = useI18n()
const { api } = useApi()
const session = useSession()
const sim = useGateSimulation()
const gate = ref<{ id: string, slug: string } | null>(null)
const failed = ref(false)
let simulatedTask = ''

interface SimulateResponse { task_id: string, gate_id: string, gate_slug: string, simulation: SimulationRow }

async function simulate(taskId: string) {
  if (!taskId || simulatedTask === taskId) return
  simulatedTask = taskId
  failed.value = false
  sim.running.value = true
  try {
    const r = await api<SimulateResponse>(`/api/gates/projects/${props.projectId}/suggestion/simulate`, { method: 'POST' })
    gate.value = { id: r.gate_id, slug: r.gate_slug }
    await sim.follow(r.simulation)
  }
  catch {
    sim.running.value = false
    failed.value = true
  }
}

// Lancer un rejeu demande le rôle operator (comme « Simuler » sur la page du gate).
function onLoaded(task: { id: string, status: string } | null) {
  if (task?.status === 'done' && session.can('operator')) void simulate(task.id)
}

const ruleLabel = (r: string) => (te(`gates.fields.${r}`) ? t(`gates.fields.${r}`) : r)
function ruleValue(v: unknown): string {
  if (v === 'none' || v === null) return t('gates.none')
  if (typeof v === 'boolean') return v ? t('gateSuggest.yes') : t('gateSuggest.no')
  if (typeof v === 'string' && te(`gates.severities.${v}`)) return t(`gates.severities.${v}`)
  return String(v)
}
function entries(v: unknown): [string, unknown][] {
  return v && typeof v === 'object' ? Object.entries(v as Record<string, unknown>) : []
}
function exceptions(v: unknown): { tool: string, rule_id: string, reason: string, expires_in_days: number }[] {
  return Array.isArray(v) ? v as { tool: string, rule_id: string, reason: string, expires_in_days: number }[] : []
}
</script>

<template>
  <AiTaskPanel
    kind="suggest-gate"
    :subject-id="projectId"
    :title="t('gateSuggest.title')"
    :ask-label="t('gateSuggest.ask')"
    icon="i-lucide-sliders-horizontal"
    @loaded="onLoaded"
  >
    <template #default="{ output, task }">
      <div
        class="space-y-3 text-sm"
        data-testid="gate-suggestion"
      >
        <dl class="grid gap-2 sm:grid-cols-2">
          <div
            v-for="[k, v] in entries(output.rules)"
            :key="k"
          >
            <dt class="text-muted">
              {{ ruleLabel(k) }}
            </dt>
            <dd>{{ ruleValue(v) }}</dd>
          </div>
        </dl>
        <p class="whitespace-pre-line">
          {{ output.rationale }}
        </p>
        <div v-if="exceptions(output.exceptions).length">
          <p class="font-medium">
            {{ t('gateSuggest.exceptions') }}
          </p>
          <ul class="list-disc ps-5">
            <li
              v-for="e in exceptions(output.exceptions)"
              :key="`${e.tool}:${e.rule_id}`"
            >
              <code>{{ e.tool }} · {{ e.rule_id }}</code> : {{ e.reason }}
              <span class="text-muted">({{ t('gateSuggest.days', { days: e.expires_in_days }) }})</span>
            </li>
          </ul>
          <p class="text-xs text-muted">
            {{ t('gateSuggest.exceptionsHelp') }}
          </p>
        </div>

        <div
          v-if="sim.running.value"
          class="flex items-center gap-2 text-muted"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="animate-spin"
          />
          {{ t('gateSim.running') }}
        </div>
        <p
          v-else-if="failed"
          class="text-warning"
        >
          {{ t('gateSuggest.simulationUnavailable') }}
        </p>
        <GatesSimulationResult
          v-else-if="sim.simulation.value?.result"
          :simulation="sim.simulation.value"
        />

        <div
          v-if="gate"
          class="flex justify-end"
        >
          <UButton
            :to="`/gates/${gate.id}?ai_task=${task.id}`"
            variant="soft"
            icon="i-lucide-arrow-right"
            :label="t('gateSuggest.open', { slug: gate.slug })"
            data-testid="gate-suggestion-open"
          />
        </div>
      </div>
    </template>
  </AiTaskPanel>
</template>
