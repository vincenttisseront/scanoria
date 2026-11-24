<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Opérations du moteur de modules (installation, mise à jour, retrait…) :
étape courante, avancement et résultat, d'après l'état publié par le helper.
-->

<script setup lang="ts">
import { isRunningOperation, type ModuleOperation } from '~/composables/useCatalog'

const props = defineProps<{ operations: ModuleOperation[], limit?: number }>()
const { t } = useI18n()
const fmt = useFormat()
const text = useModuleText()

const shown = computed(() => [...props.operations]
  .sort((a, b) => Number(isRunningOperation(b)) - Number(isRunningOperation(a)) || (b.started_at ?? '').localeCompare(a.started_at ?? ''))
  .slice(0, props.limit ?? 10))

function resultLabel(op: ModuleOperation): string {
  if (isRunningOperation(op)) return text.stepLabel(op.step) || t('request.running')
  if (op.result === 'ok') return t('catalog.operations.ok')
  if (op.result === 'failed') return t('catalog.operations.failed')
  return t('catalog.operations.finished')
}
</script>

<template>
  <p
    v-if="!shown.length"
    class="text-sm text-muted"
  >
    {{ t('catalog.operations.none') }}
  </p>
  <ul
    v-else
    class="space-y-3"
  >
    <li
      v-for="op in shown"
      :key="op.id"
      class="space-y-1 text-sm"
      :data-operation="op.id"
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <span class="flex items-center gap-2 font-medium">
          <UIcon
            v-if="isRunningOperation(op)"
            name="i-lucide-loader-circle"
            class="size-4 animate-spin"
          />
          <UIcon
            v-else
            :name="op.result === 'failed' ? 'i-lucide-circle-x' : 'i-lucide-circle-check'"
            :class="op.result === 'failed' ? 'text-error' : 'text-success'"
          />
          {{ text.operationLabel(op) }}
        </span>
        <span class="text-muted">{{ resultLabel(op) }} · {{ fmt.date(op.finished_at ?? op.started_at) }}</span>
      </div>
      <p
        v-if="op.message"
        class="text-muted"
      >
        {{ op.message }}
      </p>
      <UProgress
        v-if="isRunningOperation(op)"
        :model-value="op.progress ?? null"
        size="sm"
      />
    </li>
  </ul>
</template>
