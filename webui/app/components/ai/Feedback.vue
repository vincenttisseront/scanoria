<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Retour sur une sortie IA (I24) : 👍/👎 et correction facultative dans une
modale de la console. Le retour sert à mesurer l'accord IA/humain ; il n'est
jamais envoyé au modèle et ne change rien d'autre.
-->

<script setup lang="ts">
const props = defineProps<{
  taskId: string
  initial: { vote: 1 | -1, correction: string | null } | null
}>()

const { t } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()

const vote = ref<1 | -1 | null>(props.initial?.vote ?? null)
const busy = ref<1 | -1 | 'correction' | null>(null)
const open = ref(false)
const correction = ref(props.initial?.correction ?? '')

watch(() => props.taskId, () => {
  vote.value = props.initial?.vote ?? null
  correction.value = props.initial?.correction ?? ''
})

async function send(v: 1 | -1, text: string | null = null, kind: 1 | -1 | 'correction' = v): Promise<boolean> {
  busy.value = kind
  try {
    await api('/api/ai/feedback', { method: 'POST', body: { task_id: props.taskId, vote: v, ...(text ? { correction: text } : {}) } })
    vote.value = v
    toast.add({ title: t('ai.feedback.thanks'), color: 'success' })
    return true
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
    return false
  }
  finally {
    busy.value = null
  }
}

async function sendCorrection() {
  const text = correction.value.trim()
  if (!text) return
  if (await send(-1, text.slice(0, 4000), 'correction')) open.value = false
}
</script>

<template>
  <div
    class="flex flex-wrap items-center gap-1 text-xs"
    data-testid="ai-feedback"
  >
    <UButton
      size="xs"
      :variant="vote === 1 ? 'solid' : 'ghost'"
      color="neutral"
      icon="i-lucide-thumbs-up"
      :aria-label="t('ai.feedback.useful')"
      :title="t('ai.feedback.useful')"
      :loading="busy === 1"
      data-testid="ai-vote-up"
      @click="send(1)"
    />
    <UButton
      size="xs"
      :variant="vote === -1 ? 'solid' : 'ghost'"
      color="neutral"
      icon="i-lucide-thumbs-down"
      :aria-label="t('ai.feedback.notUseful')"
      :title="t('ai.feedback.notUseful')"
      :loading="busy === -1"
      data-testid="ai-vote-down"
      @click="send(-1)"
    />
    <UButton
      size="xs"
      variant="ghost"
      color="neutral"
      icon="i-lucide-pencil"
      :label="t('ai.feedback.correct')"
      data-testid="ai-correct"
      @click="open = true"
    />
    <UModal
      v-model:open="open"
      :title="t('ai.feedback.correctionTitle')"
      :dismissible="busy !== 'correction'"
    >
      <template #body>
        <div class="space-y-3">
          <p class="text-sm text-muted">
            {{ t('ai.feedback.correctionHelp') }}
          </p>
          <UFormField :label="t('ai.feedback.correctionLabel')">
            <UTextarea
              v-model="correction"
              :rows="4"
              :maxlength="4000"
              class="w-full"
              data-testid="ai-correction"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :label="t('common.cancel')"
            :disabled="busy === 'correction'"
            @click="open = false"
          />
          <UButton
            :label="t('ai.feedback.send')"
            :loading="busy === 'correction'"
            :disabled="!correction.trim()"
            data-testid="ai-correction-send"
            @click="sendCorrection"
          />
        </div>
      </template>
    </UModal>
  </div>
</template>
