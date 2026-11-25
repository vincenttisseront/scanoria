<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Recherche en langage naturel (I8, 0.7) : une phrase est traduite par l'IA en
filtres structurés de la console (jamais en SQL), affichés sous forme de
pastilles que l'on peut retirer avant de les appliquer. L'exécution reste
celle de la page (GET /api/findings ou /api/components), avec les droits de
la personne. Indicateur d'attente pendant la traduction ; rien n'est affiché
sans connecteur, et la recherche classique reste identique.
-->

<script setup lang="ts">
type Target = 'findings' | 'components'
interface Chip { key: string, value: string }
interface Resolved { target: Target, query: Record<string, string>, chips: Chip[], explanation: string, unsupported: string[] }
interface SearchState {
  enabled: boolean
  task: { id: string, status: string, error: string | null, model: string | null, model_digest: string | null } | null
  result: Resolved | null
}

const props = defineProps<{ target: Target }>()
/** query : paramètres de l'API de la page ; labels : valeur affichée de chaque filtre (slug du projet). */
const emit = defineEmits<{ apply: [query: Record<string, string>, labels: Record<string, string>] }>()
const { t, te, locale } = useI18n()
const { api, errorMessage } = useApi()

const enabled = ref(false)
const phrase = ref('')
const subjectId = ref<string | null>(null)
const state = ref<SearchState | null>(null)
const requesting = ref(false)
const failure = ref('')
const removed = ref<Set<string>>(new Set())
let timer: ReturnType<typeof setTimeout> | null = null
let disposed = false

const pending = computed(() => requesting.value || state.value?.task?.status === 'queued' || state.value?.task?.status === 'running')
const result = computed(() => (state.value?.task?.status === 'done' ? state.value.result : null))
const chips = computed(() => (result.value?.chips ?? []).filter(c => !removed.value.has(c.key)))
const otherPage = computed(() => (result.value && result.value.target !== props.target ? result.value.target : null))
const mark = computed(() => {
  const task = state.value?.task
  if (!task?.model) return ''
  const digest = task.model_digest ? ` (${task.model_digest.slice(0, 12)})` : ''
  return t('ai.explain.mark', { model: `${task.model}${digest}` })
})
const errorReason = computed(() => {
  const e = state.value?.task?.error ?? ''
  return te(`ai.errors.${e}`) ? t(`ai.errors.${e}`) : t('ai.errors.internal')
})

function chipLabel(c: Chip): string {
  const name = te(`ai.nlSearch.keys.${c.key}`) ? t(`ai.nlSearch.keys.${c.key}`) : c.key
  return c.value === 'true' ? name : `${name} : ${c.value}`
}

function stop() {
  if (timer) clearTimeout(timer)
  timer = null
}

async function poll() {
  stop()
  if (!subjectId.value || disposed) return
  try {
    state.value = await api<SearchState>('/api/ai/search', { query: { subject_id: subjectId.value, locale: locale.value } })
  }
  catch (err) {
    failure.value = errorMessage(err)
    state.value = null
    return
  }
  if (pending.value && !disposed) timer = setTimeout(poll, 1500)
}

async function translate() {
  const text = phrase.value.trim()
  if (text.length < 3) return
  stop()
  failure.value = ''
  removed.value = new Set()
  state.value = null
  requesting.value = true
  try {
    const r = await api<{ subject_id: string | null }>('/api/ai/search', {
      method: 'POST',
      body: { phrase: text, target: 'auto', locale: locale.value },
    })
    subjectId.value = r.subject_id
    if (!r.subject_id) failure.value = t('ai.errors.connector-disabled')
  }
  catch (err) {
    failure.value = errorMessage(err)
  }
  finally {
    requesting.value = false
  }
  await poll()
}

function remove(key: string) {
  removed.value = new Set([...removed.value, key])
}

function kept(): Record<string, string> {
  const q = result.value?.query ?? {}
  return Object.fromEntries(Object.entries(q).filter(([k]) => !removed.value.has(k)))
}

function apply() {
  if (!result.value) return
  const q = kept()
  if (otherPage.value === 'findings') {
    void navigateTo({ path: '/findings', query: q })
    return
  }
  if (otherPage.value === 'components') {
    // Adresse de la page Composants : q, from et to plutôt que name et version.
    const { name, version, ...rest } = q
    void navigateTo({ path: '/components', query: { ...rest, q: name, from: version, to: version } })
    return
  }
  emit('apply', q, Object.fromEntries(chips.value.map(c => [c.key, c.value])))
}

onMounted(async () => {
  try {
    enabled.value = (await api<SearchState>('/api/ai/search')).enabled
  }
  catch {
    enabled.value = false
  }
})
onBeforeUnmount(() => {
  disposed = true
  stop()
})
</script>

<template>
  <section
    v-if="enabled"
    class="space-y-2 rounded-md border border-default p-3 text-sm"
    data-testid="ai-nl-search"
  >
    <form
      class="flex flex-wrap items-center gap-2"
      @submit.prevent="translate"
    >
      <UIcon
        name="i-lucide-sparkles"
        class="text-muted"
      />
      <UInput
        v-model="phrase"
        class="min-w-64 flex-1"
        :maxlength="300"
        :placeholder="t(`ai.nlSearch.placeholder.${target}`)"
        :aria-label="t('ai.nlSearch.label')"
        data-testid="ai-nl-phrase"
      />
      <UButton
        type="submit"
        size="sm"
        variant="outline"
        :loading="pending"
        :disabled="phrase.trim().length < 3"
        :label="t('ai.nlSearch.translate')"
        data-testid="ai-nl-translate"
      />
    </form>

    <div
      v-if="pending"
      class="flex items-center gap-2 text-muted"
      data-testid="ai-pending"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('ai.nlSearch.pending') }}
    </div>

    <p
      v-else-if="failure"
      class="text-muted"
    >
      {{ failure }}
    </p>

    <p
      v-else-if="state?.task && (state.task.status === 'error' || state.task.status === 'skipped')"
      class="text-muted"
    >
      {{ t('ai.explain.unavailable', { reason: errorReason }) }}
    </p>

    <div
      v-else-if="result"
      class="space-y-2"
      data-testid="ai-nl-result"
    >
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-muted">{{ t('ai.nlSearch.filters') }}</span>
        <UBadge
          v-for="c in chips"
          :key="c.key"
          color="primary"
          variant="subtle"
          class="gap-1"
          :data-testid="`ai-nl-chip-${c.key}`"
        >
          {{ chipLabel(c) }}
          <UButton
            size="xs"
            variant="link"
            color="neutral"
            icon="i-lucide-x"
            :aria-label="t('ai.nlSearch.remove', { filter: chipLabel(c) })"
            @click="remove(c.key)"
          />
        </UBadge>
        <span
          v-if="!chips.length"
          class="text-muted"
        >{{ t('ai.nlSearch.none') }}</span>
        <UBadge
          v-if="mark"
          color="neutral"
          variant="subtle"
          :label="mark"
          data-testid="ai-mark"
        />
      </div>
      <p class="text-muted">
        {{ result.explanation }}
      </p>
      <p
        v-if="result.unsupported.length"
        class="text-xs text-muted"
        data-testid="ai-nl-unsupported"
      >
        {{ t('ai.nlSearch.unsupported', { parts: result.unsupported.join(', ') }) }}
      </p>
      <div class="flex flex-wrap items-center gap-2">
        <UButton
          size="sm"
          icon="i-lucide-filter"
          :label="otherPage ? t(`ai.nlSearch.openOther.${otherPage}`) : t('ai.nlSearch.apply')"
          data-testid="ai-nl-apply"
          @click="apply"
        />
        <span class="text-xs text-muted">{{ t('ai.nlSearch.reviewHint') }}</span>
      </div>
    </div>
  </section>
</template>
