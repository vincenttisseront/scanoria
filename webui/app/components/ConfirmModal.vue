<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Modale de confirmation de la console (jamais la boîte native du navigateur). Avec « ack »,
une case doit être cochée avant de confirmer.
-->

<script setup lang="ts">
const props = withDefaults(defineProps<{
  title: string
  body?: string
  confirmLabel?: string
  color?: 'primary' | 'error' | 'warning' | 'neutral'
  loading?: boolean
  ack?: string
}>(), {
  body: '',
  confirmLabel: undefined,
  color: 'primary',
  loading: false,
  ack: undefined,
})

const emit = defineEmits<{ confirm: [] }>()
const open = defineModel<boolean>('open', { default: false })
const acknowledged = ref(false)
const { t } = useI18n()

watch(open, (value) => {
  if (value) acknowledged.value = false
})

const canConfirm = computed(() => !props.ack || acknowledged.value)
</script>

<template>
  <UModal
    v-model:open="open"
    :title="title"
    :dismissible="!loading"
  >
    <template #body>
      <div class="space-y-4">
        <p
          v-if="body"
          class="text-sm text-muted whitespace-pre-line"
        >
          {{ body }}
        </p>
        <slot />
        <UCheckbox
          v-if="ack"
          v-model="acknowledged"
          :label="ack"
        />
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton
          color="neutral"
          variant="ghost"
          :disabled="loading"
          :label="t('common.cancel')"
          @click="open = false"
        />
        <UButton
          :color="color"
          :loading="loading"
          :disabled="!canConfirm"
          :label="confirmLabel ?? t('common.confirm')"
          @click="emit('confirm')"
        />
      </div>
    </template>
  </UModal>
</template>
