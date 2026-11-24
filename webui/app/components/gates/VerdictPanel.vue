<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Verdict d'une analyse (quality gate, ARCHITECTURE § 12.7) : verdict, raisons dans
l'ordre de l'évaluateur, actions qui débloqueraient, exceptions appliquées.
Utilisé par la page d'analyse (chantier C). Le slot « ai » reçoit le texte
d'explication de l'IA (I9, chantier F) ; à défaut, aiSummary est affiché tel
quel, marqué « proposé par IA ». L'IA n'entre jamais dans le verdict.
-->

<script setup lang="ts">
import type { VerdictDetails } from '#shared/analysis'

type Reason = VerdictDetails['reasons'][number]

const props = withDefaults(defineProps<{
  details: VerdictDetails | null
  scanId?: string
  projectId?: string
  aiSummary?: { summary: string, model: string | null } | null
}>(), {
  scanId: undefined,
  projectId: undefined,
  aiSummary: null,
})

const { t, te } = useI18n()
const fmt = useFormat()

const COLORS = { passed: 'success', failed: 'error', inconclusive: 'warning' } as const
const ICONS = { passed: 'i-lucide-circle-check', failed: 'i-lucide-circle-x', inconclusive: 'i-lucide-circle-question-mark' } as const

const blocking = computed(() => props.details?.reasons.filter(r => r.blocking) ?? [])
const informative = computed(() => props.details?.reasons.filter(r => !r.blocking) ?? [])

function reasonLabel(r: Reason): string {
  const base = t(`gates.reasons.${r.code}`, { count: r.count })
  const parts = [base]
  if (r.severity) parts.push(t(`gates.severities.${r.severity}`))
  if (r.module) parts.push(r.module)
  return parts.join(' · ')
}

function actionLink(r: Reason, action: Reason['actions'][number]): string | undefined {
  switch (action) {
    case 'fix':
      if (!props.scanId) return undefined
      return r.finding_ids.length ? `/findings?scan=${props.scanId}&ids=${r.finding_ids.slice(0, 20).join(',')}` : `/findings?scan=${props.scanId}`
    case 'request-exception':
      return props.projectId ? `/findings?project=${props.projectId}&exception=1` : undefined
    case 'install-module':
    case 'refresh-feed':
      return '/catalog'
    case 'rerun':
      return props.scanId ? `/scans/${props.scanId}` : undefined
    default:
      return undefined
  }
}

function actionLabel(action: string): string {
  return te(`gates.actions.${action}`) ? t(`gates.actions.${action}`) : action
}
</script>

<template>
  <UCard data-testid="verdict-panel">
    <template #header>
      <div class="flex flex-wrap items-center gap-3">
        <template v-if="details">
          <UBadge
            :color="COLORS[details.verdict]"
            :icon="ICONS[details.verdict]"
            size="lg"
            variant="subtle"
            :label="t(`gates.verdicts.${details.verdict}`)"
          />
          <span class="text-sm text-muted">
            {{ t('gates.panel.evaluated', { date: fmt.date(details.evaluated_at) }) }}
            · {{ details.new_code_only ? t('gates.panel.newCodeOnly') : t('gates.panel.allCode') }}
          </span>
        </template>
        <span
          v-else
          class="text-sm text-muted"
        >{{ t('gates.panel.pending') }}</span>
      </div>
    </template>

    <div
      v-if="details"
      class="space-y-4"
    >
      <p class="text-sm">
        {{ t(`gates.panel.explain.${details.verdict}`) }}
      </p>

      <div
        v-if="$slots.ai || aiSummary"
        class="rounded-md border border-default p-3"
        data-testid="verdict-ai"
      >
        <slot name="ai">
          <p class="mb-1 text-xs text-muted">
            {{ t('gates.panel.aiProposed', { model: aiSummary?.model ?? '?' }) }}
          </p>
          <p class="text-sm whitespace-pre-line">
            {{ aiSummary?.summary }}
          </p>
        </slot>
      </div>

      <div class="flex flex-wrap gap-2 text-xs">
        <UBadge
          v-for="(n, sev) in details.counts"
          :key="sev"
          color="neutral"
          variant="outline"
          :label="`${t(`gates.severities.${sev}`)} : ${n}`"
        />
      </div>

      <div v-if="blocking.length">
        <h3 class="mb-2 text-sm font-semibold">
          {{ t('gates.panel.blocking') }}
        </h3>
        <ol class="space-y-2">
          <li
            v-for="(r, i) in blocking"
            :key="`b${i}`"
            class="flex flex-wrap items-center gap-2 text-sm"
            data-testid="verdict-reason"
          >
            <UIcon
              name="i-lucide-octagon-x"
              class="text-error"
            />
            <span>{{ reasonLabel(r) }}</span>
            <template
              v-for="a in r.actions"
              :key="a"
            >
              <UButton
                v-if="actionLink(r, a)"
                size="xs"
                variant="soft"
                :to="actionLink(r, a)"
                :label="actionLabel(a)"
              />
              <UBadge
                v-else
                size="sm"
                variant="soft"
                color="neutral"
                :label="actionLabel(a)"
              />
            </template>
          </li>
        </ol>
      </div>

      <div v-if="informative.length">
        <h3 class="mb-2 text-sm font-semibold">
          {{ t('gates.panel.informative') }}
        </h3>
        <ul class="space-y-1">
          <li
            v-for="(r, i) in informative"
            :key="`i${i}`"
            class="flex items-center gap-2 text-sm text-muted"
          >
            <UIcon name="i-lucide-info" />
            <span>{{ reasonLabel(r) }}</span>
          </li>
        </ul>
      </div>

      <div v-if="details.exceptions_applied.length">
        <h3 class="mb-2 text-sm font-semibold">
          {{ t('gates.panel.exceptions') }}
        </h3>
        <ul class="space-y-1">
          <li
            v-for="e in details.exceptions_applied"
            :key="e.id"
            class="text-sm"
          >
            {{ t('gates.panel.exceptionUntil', { date: e.expires_on }) }} — {{ e.reason }}
          </li>
        </ul>
      </div>
    </div>
  </UCard>
</template>
