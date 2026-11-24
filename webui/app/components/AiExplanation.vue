<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Explication proposée par IA (CLAUDE.md § 3.5, I2 et I9) pour un résultat
(kind « explain-finding », subject-id = id du résultat) ou un verdict
(kind « explain-verdict », subject-id = id de l'analyse). Texte brut seulement
(déjà échappé côté serveur, affiché par interpolation), mention « proposé par
IA » avec le modèle et son empreinte. Ne rend rien sans connecteur (ni les
explications déjà produites) : la page reste identique. Lecture seule : aucune action ne découle de ce texte.
-->

<script setup lang="ts">
interface Reference { label: string, url: string }
interface AiOutput {
  summary?: string
  detects?: string
  risk?: string
  impact?: string
  fix?: string
  references?: Reference[]
  blocking?: string
  actions?: string[]
}
interface OutputResponse {
  enabled: boolean
  opt_out: boolean
  task: {
    id: string
    status: 'queued' | 'running' | 'done' | 'error'
    locale: string
    error: string | null
    output: AiOutput | null
    model: string | null
    model_digest: string | null
    generated_at: string | null
    stale?: boolean
  } | null
}

const props = withDefaults(defineProps<{
  kind: 'explain-finding' | 'explain-verdict'
  subjectId: string
  pollMs?: number
}>(), { pollMs: 3000 })

const { t, te, locale } = useI18n()
const { api } = useApi()

const data = ref<OutputResponse | null>(null)
const requesting = ref(false)
let timer: ReturnType<typeof setTimeout> | null = null
let disposed = false

const pending = computed(() => requesting.value || data.value?.task?.status === 'queued' || data.value?.task?.status === 'running')
const visible = computed(() => !!data.value?.enabled)
const output = computed(() => (data.value?.task?.status === 'done' ? data.value.task.output : null))
const title = computed(() => t(props.kind === 'explain-verdict' ? 'ai.explain.verdictTitle' : 'ai.explain.title'))
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
const sections = computed(() => {
  const o = output.value
  if (!o || props.kind !== 'explain-finding') return []
  return (['detects', 'risk', 'impact', 'fix'] as const)
    .filter(k => typeof o[k] === 'string' && o[k])
    .map(k => ({ key: k, label: t(`ai.explain.${k}`), text: o[k] as string }))
})
/** Liens déjà filtrés par le serveur ; revérifiés ici (https vers une référence connue, ou chemin de la console). */
const SAFE_LINK = /^(https:\/\/(cwe\.mitre\.org|www\.cve\.org|cve\.org|nvd\.nist\.gov|osv\.dev)\/|\/(?!\/))/
const references = computed(() => (output.value?.references ?? []).filter(r => SAFE_LINK.test(r.url)))

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
  schedule()
}

async function ask() {
  if (requesting.value) return
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

watch(() => [props.kind, props.subjectId, locale.value], load)
onMounted(load)
onBeforeUnmount(() => {
  disposed = true
  if (timer) clearTimeout(timer)
})
</script>

<template>
  <section
    v-if="visible && data"
    class="space-y-2 rounded-md border border-default p-3 text-sm"
    data-testid="ai-explanation"
  >
    <div class="flex items-center justify-between gap-2">
      <h3 class="flex items-center gap-1 font-semibold">
        <UIcon name="i-lucide-sparkles" />
        {{ title }}
      </h3>
      <UBadge
        v-if="mark && output"
        color="neutral"
        variant="subtle"
        :label="mark"
      />
    </div>

    <p
      v-if="data.opt_out"
      class="text-muted"
    >
      {{ t('ai.explain.optOut') }}
    </p>

    <div
      v-else-if="pending"
      class="flex items-center gap-2 text-muted"
      data-testid="ai-pending"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('ai.explain.pending') }}
    </div>

    <template v-else-if="output">
      <p class="whitespace-pre-line">
        {{ output.summary }}
      </p>
      <template v-if="kind === 'explain-finding'">
        <div
          v-for="s in sections"
          :key="s.key"
        >
          <p class="font-medium">
            {{ s.label }}
          </p>
          <p class="whitespace-pre-line text-muted">
            {{ s.text }}
          </p>
        </div>
        <div v-if="references.length">
          <p class="font-medium">
            {{ t('ai.explain.references') }}
          </p>
          <ul class="list-disc pl-5">
            <li
              v-for="r in references"
              :key="r.url"
            >
              <a
                :href="r.url"
                target="_blank"
                rel="noopener noreferrer nofollow"
                class="text-primary underline"
              >{{ r.label }}</a>
            </li>
          </ul>
        </div>
      </template>
      <template v-else>
        <div v-if="output.blocking">
          <p class="font-medium">
            {{ t('ai.explain.blocking') }}
          </p>
          <p class="text-muted">
            {{ output.blocking }}
          </p>
        </div>
        <div v-if="output.actions?.length">
          <p class="font-medium">
            {{ t('ai.explain.actions') }}
          </p>
          <ol class="list-decimal pl-5">
            <li
              v-for="(a, i) in output.actions"
              :key="i"
            >
              {{ a }}
            </li>
          </ol>
        </div>
      </template>
      <div
        v-if="data.task?.stale"
        class="flex flex-wrap items-center gap-2 text-xs text-muted"
      >
        <span>{{ t('ai.explain.stale') }}</span>
        <UButton
          size="xs"
          variant="outline"
          icon="i-lucide-rotate-cw"
          :loading="requesting"
          :disabled="requesting"
          :label="t('ai.explain.ask')"
          @click="ask"
        />
      </div>
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
        :loading="requesting"
        :disabled="requesting"
        :label="t('ai.explain.retry')"
        @click="ask"
      />
    </div>

    <UButton
      v-else
      size="sm"
      variant="outline"
      icon="i-lucide-sparkles"
      :loading="requesting"
      :label="t('ai.explain.ask')"
      @click="ask"
    />
  </section>
</template>
