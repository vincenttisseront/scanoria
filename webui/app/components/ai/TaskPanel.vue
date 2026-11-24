<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Cadre commun d'une sortie IA de la 0.4 (CLAUDE.md § 3.5) : lecture de la
dernière sortie (/api/ai/output), indicateur d'attente et rafraîchissement
sans recharger la page, demande interactive, mention « proposé par IA » avec
le modèle et son empreinte, retour 👍/👎 (I24). Texte brut seulement, déjà
échappé côté serveur et affiché par interpolation. Ne rend rien sans
connecteur : la page reste identique. Le contenu propre à chaque tâche est
rendu par le slot par défaut, qui reçoit la sortie.
-->

<script setup lang="ts">
export interface AiTask {
  id: string
  status: 'queued' | 'running' | 'done' | 'error' | 'skipped'
  locale: string
  error: string | null
  output: Record<string, unknown> | null
  model: string | null
  model_digest: string | null
  generated_at: string | null
  stale?: boolean
  feedback?: { vote: 1 | -1, correction: string | null } | null
}
interface OutputResponse { enabled: boolean, opt_out: boolean, task: AiTask | null }

const props = withDefaults(defineProps<{
  kind: string
  subjectId: string
  title: string
  icon?: string
  /** Demander la sortie à l'ouverture si elle n'existe pas encore (précalcul absent). */
  autoAsk?: boolean
  /** Bouton de demande affiché quand rien n'existe encore. */
  askLabel?: string
  pollMs?: number
  compact?: boolean
  /** Faux : rien n'est affiché tant qu'aucune tâche n'existe (sortie seulement précalculée). */
  askable?: boolean
}>(), { icon: 'i-lucide-sparkles', autoAsk: false, askLabel: undefined, pollMs: 3000, compact: false, askable: true })

const emit = defineEmits<{ loaded: [task: AiTask | null] }>()
const { t, te, locale } = useI18n()
const { api } = useApi()

const data = ref<OutputResponse | null>(null)
const requesting = ref(false)
let timer: ReturnType<typeof setTimeout> | null = null
let disposed = false
let asked = false

const pending = computed(() => requesting.value || data.value?.task?.status === 'queued' || data.value?.task?.status === 'running')
const output = computed(() => (data.value?.task?.status === 'done' ? data.value.task.output : null))
const mark = computed(() => {
  const task = data.value?.task
  if (!task?.model) return ''
  const digest = task.model_digest ? ` (${task.model_digest.slice(0, 12)})` : ''
  return t('ai.explain.mark', { model: `${task.model}${digest}` })
})
const errorReason = computed(() => {
  const e = data.value?.task?.error ?? ''
  return te(`ai.errors.${e}`) ? t(`ai.errors.${e}`) : t('ai.errors.internal')
})

function schedule() {
  if (timer) clearTimeout(timer)
  timer = null
  if (!disposed && pending.value) timer = setTimeout(load, props.pollMs)
}

async function load() {
  try {
    data.value = await api<OutputResponse>('/api/ai/output', { query: { kind: props.kind, subject_id: props.subjectId, locale: locale.value } })
  }
  catch {
    data.value = null
  }
  emit('loaded', data.value?.task ?? null)
  if (props.autoAsk && !asked && data.value?.enabled && !data.value.opt_out && !data.value.task) {
    asked = true
    await ask()
    return
  }
  schedule()
}

async function ask() {
  requesting.value = true
  try {
    await api('/api/ai/explain', { method: 'POST', body: { kind: props.kind, subject_id: props.subjectId, locale: locale.value } })
  }
  catch {
    // L'erreur éventuelle apparaîtra au rechargement de la sortie.
  }
  finally {
    requesting.value = false
  }
  await load()
}

watch(() => [props.kind, props.subjectId, locale.value], () => {
  asked = false
  void load()
})
onMounted(load)
onBeforeUnmount(() => {
  disposed = true
  if (timer) clearTimeout(timer)
})
defineExpose({ reload: load })
</script>

<template>
  <section
    v-if="data?.enabled && !data.opt_out && (askable || data.task || requesting)"
    class="space-y-2 rounded-md border border-default text-sm"
    :class="compact ? 'p-2' : 'p-3'"
    :data-testid="`ai-panel-${kind}`"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="flex items-center gap-1 font-semibold">
        <UIcon :name="icon" />
        {{ title }}
      </h3>
      <UBadge
        v-if="mark && output"
        color="neutral"
        variant="subtle"
        :label="mark"
        data-testid="ai-mark"
      />
    </div>

    <div
      v-if="pending"
      class="flex items-center gap-2 text-muted"
      data-testid="ai-pending"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('ai.explain.pending') }}
    </div>

    <template v-else-if="output && data.task">
      <slot
        :output="output"
        :task="data.task"
      />
      <div
        v-if="data.task.stale"
        class="flex flex-wrap items-center gap-2 text-xs text-muted"
      >
        <span>{{ t('ai.explain.stale') }}</span>
        <UButton
          size="xs"
          variant="outline"
          icon="i-lucide-rotate-cw"
          :label="t('ai.explain.retry')"
          @click="ask"
        />
      </div>
      <AiFeedback
        :task-id="data.task.id"
        :initial="data.task.feedback ?? null"
      />
    </template>

    <div
      v-else-if="data.task?.status === 'error'"
      class="flex flex-wrap items-center gap-2"
    >
      <span class="text-muted">{{ t('ai.explain.unavailable', { reason: errorReason }) }}</span>
      <UButton
        size="xs"
        variant="outline"
        icon="i-lucide-rotate-cw"
        :label="t('ai.explain.retry')"
        @click="ask"
      />
    </div>

    <p
      v-else-if="data.task?.status === 'skipped'"
      class="text-muted"
    >
      {{ t('ai.explain.unavailable', { reason: errorReason }) }}
    </p>

    <UButton
      v-else-if="askable"
      size="sm"
      variant="outline"
      icon="i-lucide-sparkles"
      :loading="requesting"
      :label="askLabel ?? t('ai.explain.ask')"
      @click="ask"
    />
  </section>
</template>
