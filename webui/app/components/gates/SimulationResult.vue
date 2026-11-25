<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

F9 : effet d'une simulation de quality gate. Analyses et releases qui
auraient été bloquées, débloquées ou inchangées, règles responsables, et la
liste des analyses concernées avec un lien vers chacune. Le verdict réel est
montré à côté du rejeu ; un écart entre les deux (tri humain changé depuis)
est signalé à part.
-->

<script setup lang="ts">
import type { SimulationRow } from '~/composables/useGateSimulation'

const props = defineProps<{ simulation: SimulationRow }>()
const { t, te } = useI18n()
const fmt = useFormat()

const result = computed(() => props.simulation.result)
const changed = computed(() => (result.value?.items ?? []).filter(i => i.effect !== 'unchanged' || i.release).slice(0, 100))
const ruleLabel = (r: string) => (te(`gates.fields.${r}`) ? t(`gates.fields.${r}`) : r)
const effectColor = (e: string) => (e === 'blocked' ? 'error' : e === 'unblocked' ? 'warning' : 'neutral')
</script>

<template>
  <div
    v-if="result"
    class="space-y-4 text-sm"
    data-testid="simulation-result"
  >
    <div class="grid gap-3 sm:grid-cols-2">
      <div class="rounded-md border border-default p-3">
        <p class="font-medium">
          {{ t('gateSim.scansTitle', { n: result.scans.total }) }}
        </p>
        <p data-testid="simulation-scans">
          <span class="text-error">{{ t('gateSim.blocked', { n: result.scans.blocked }) }}</span> ·
          <span class="text-warning">{{ t('gateSim.unblocked', { n: result.scans.unblocked }) }}</span> ·
          {{ t('gateSim.unchanged', { n: result.scans.unchanged }) }}
        </p>
      </div>
      <div class="rounded-md border border-default p-3">
        <p class="font-medium">
          {{ t('gateSim.releasesTitle', { n: result.releases.total }) }}
        </p>
        <p data-testid="simulation-releases">
          <span class="text-error">{{ t('gateSim.blocked', { n: result.releases.blocked }) }}</span> ·
          <span class="text-warning">{{ t('gateSim.unblocked', { n: result.releases.unblocked }) }}</span> ·
          {{ t('gateSim.unchanged', { n: result.releases.unchanged }) }}
        </p>
      </div>
    </div>

    <p class="text-xs text-muted">
      {{ t('gateSim.since', { date: fmt.date(result.since) }) }}
      <template v-if="result.scans.drift">
        · {{ t('gateSim.drift', { n: result.scans.drift }) }}
      </template>
      <template v-if="result.scans.errors">
        · {{ t('gateSim.errors', { n: result.scans.errors }) }}
      </template>
      <template v-if="result.limited">
        · {{ t('gateSim.limited') }}
      </template>
    </p>

    <div v-if="result.by_rule.length">
      <p class="font-medium">
        {{ t('gateSim.byRule') }}
      </p>
      <ul class="list-disc ps-5">
        <li
          v-for="r in result.by_rule"
          :key="r.rule"
        >
          {{ ruleLabel(r.rule) }} :
          {{ t('gateSim.blocked', { n: r.blocked }) }} · {{ t('gateSim.unblocked', { n: r.unblocked }) }}
        </li>
      </ul>
    </div>
    <p
      v-else
      class="text-muted"
    >
      {{ t('gateSim.noEffect') }}
    </p>

    <ul
      v-if="changed.length"
      class="divide-y divide-default rounded-md border border-default"
    >
      <li
        v-for="i in changed"
        :key="i.scan_id"
        class="flex flex-wrap items-center gap-2 px-3 py-2"
      >
        <UBadge
          :color="effectColor(i.effect)"
          variant="subtle"
          size="sm"
          :label="t(`gateSim.effects.${i.effect}`)"
        />
        <ULink :to="`/scans/${i.scan_id}`">
          {{ i.project_slug }} · n° {{ i.number }}
        </ULink>
        <UBadge
          v-if="i.release"
          color="primary"
          variant="soft"
          size="sm"
          :label="i.tag ?? t('gateSim.release')"
        />
        <span class="text-xs text-muted">{{ i.ref }} · {{ fmt.date(i.finished_at) }}</span>
        <span class="text-xs">
          {{ t(`gates.verdicts.${i.replay}`) }} → {{ t(`gates.verdicts.${i.simulated}`) }}
        </span>
        <span
          v-if="i.rules.length"
          class="text-xs text-muted"
        >({{ i.rules.map(ruleLabel).join(', ') }})</span>
      </li>
    </ul>
    <p
      v-if="result.truncated"
      class="text-xs text-muted"
    >
      {{ t('gateSim.truncated') }}
    </p>
  </div>
</template>
