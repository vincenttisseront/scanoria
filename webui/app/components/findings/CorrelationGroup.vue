<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'un résultat (0.5) : exploitation (EPSS, KEV) et groupe de résultats
recoupés (F16), avec un lien vers chaque résultat d'origine. La case « appliquer
au groupe » est reprise par la page pour trier tout le groupe en une fois.
-->

<script setup lang="ts">
interface Member { id: string, tool: string, severity: string, status: string }
interface Group { confirmations: number, tools: string[], members: Member[], size?: number }
const props = defineProps<{
  findingId: string
  epss: number | null | undefined
  epssPercentile: number | null | undefined
  kev: boolean | null | undefined
  kevAdded?: string | null
  vulnerability: boolean
  group: Group | null | undefined
}>()
const applyToGroup = defineModel<boolean>('applyToGroup', { default: true })
const emit = defineEmits<{ open: [id: string] }>()
const { t } = useI18n()
const others = computed(() => (props.group?.members ?? []).filter(m => m.id !== props.findingId))
</script>

<template>
  <div class="space-y-3">
    <UCard
      v-if="vulnerability"
      data-testid="intel-detail"
    >
      <template #header>
        <p class="font-medium">
          {{ t('intel.detail.title') }}
        </p>
      </template>
      <dl class="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <div>
          <dt class="text-muted">
            {{ t('intel.detail.epss') }}
          </dt>
          <dd>
            <FindingsIntelBadges
              :epss="epss"
              :epss-percentile="epssPercentile"
              :kev="false"
            />
            <span
              v-if="typeof epss === 'number'"
              class="ms-1 text-xs text-muted"
              data-testid="epss-attribution-detail"
            >{{ t('intel.attribution') }}</span>
          </dd>
        </div>
        <div>
          <dt class="text-muted">
            {{ t('intel.detail.kev') }}
          </dt>
          <dd>{{ kev ? (kevAdded ? t('intel.detail.kevYes', { date: kevAdded }) : t('intel.detail.kevYesNoDate')) : t('intel.detail.kevNo') }}</dd>
        </div>
      </dl>
      <p class="mt-2 text-xs text-muted">
        {{ t('intel.detail.gate') }}
      </p>
    </UCard>

    <UCard
      v-if="group && group.members.length > 1"
      data-testid="correlation-group"
    >
      <template #header>
        <div class="flex flex-wrap items-center gap-2">
          <p class="font-medium">
            {{ t('intel.correlation.title') }}
          </p>
          <FindingsCorrelationBadge :group="group" />
        </div>
      </template>
      <ul class="space-y-1">
        <li
          v-for="m in others"
          :key="m.id"
          class="flex flex-wrap items-center gap-2"
        >
          <FindingsSeverityBadge :severity="m.severity" />
          <span class="font-mono text-xs">{{ m.tool }}</span>
          <UButton
            size="xs"
            variant="link"
            icon="i-lucide-arrow-right"
            :label="t('intel.correlation.open')"
            :data-testid="`correlation-open-${m.id}`"
            @click="emit('open', m.id)"
          />
        </li>
      </ul>
      <UCheckbox
        v-model="applyToGroup"
        class="mt-3"
        :label="t('intel.correlation.applyToGroup', { count: group.size ?? group.members.length })"
        :description="t('intel.correlation.applyToGroupHelp')"
        data-testid="apply-to-group"
      />
    </UCard>
  </div>
</template>
