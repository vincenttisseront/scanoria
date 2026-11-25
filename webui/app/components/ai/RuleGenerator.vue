<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Générateur de règles (I12, 0.7) : depuis un résultat, un exemple de code ou
une phrase, l'IA propose une règle Opengrep/Semgrep, un motif gitleaks ou une
politique Checkov, avec un exemple positif et un négatif. La règle est
aussitôt testée dans le conteneur confiné du moteur ; seul un administrateur
peut l'enregistrer dans un jeu de règles géré (G4), après une modale de
confirmation, et seulement si le test passe. Rien n'est enregistré
automatiquement. Texte brut uniquement, affiché par interpolation. Rien sans
connecteur.
-->

<script setup lang="ts">
type Engine = 'opengrep' | 'semgrep' | 'gitleaks' | 'checkov'
type Source = 'finding' | 'example' | 'phrase'
interface Sample { filename: string, content: string }
interface RuleOutput { rule_id: string, rule: string, positive: Sample, negative: Sample, explanation: string }
interface RuleState {
  enabled: boolean
  available: boolean
  engine: Engine | null
  task: { id: string, status: string, error: string | null, output: RuleOutput | null, model: string | null, model_digest: string | null } | null
}
interface Verdict { passed: boolean, positive_matches: number, negative_matches: number, errors: string[] }
interface Ruleset { id: string, slug: string, name: string, latest_version: number | null }

const props = withDefaults(defineProps<{ findingId?: string, defaultEngine?: Engine }>(), { findingId: undefined, defaultEngine: 'opengrep' })
const { t, te, locale } = useI18n()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()

const ENGINES: Engine[] = ['opengrep', 'semgrep', 'gitleaks', 'checkov']
const engineItems = ENGINES.map(e => ({ label: e, value: e }))
const sourceItems = computed(() => [
  ...(props.findingId ? [{ label: t('ai.rulegen.sources.finding'), value: 'finding' }] : []),
  { label: t('ai.rulegen.sources.example'), value: 'example' },
  { label: t('ai.rulegen.sources.phrase'), value: 'phrase' },
])

const enabled = ref(false)
const available = ref(false)
const form = reactive({
  engine: props.defaultEngine as Engine,
  source: (props.findingId ? 'finding' : 'phrase') as Source,
  description: '',
  example: '',
  language: '',
})
const subjectId = ref<string | null>(null)
const state = ref<RuleState | null>(null)
const requesting = ref(false)
const failure = ref('')
const testing = ref(false)
const verdict = ref<Verdict | null>(null)
let timer: ReturnType<typeof setTimeout> | null = null
let disposed = false

const pending = computed(() => requesting.value || state.value?.task?.status === 'queued' || state.value?.task?.status === 'running')
const output = computed(() => (state.value?.task?.status === 'done' ? state.value.task.output : null))
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
const canGenerate = computed(() => {
  if (form.source === 'finding') return !!props.findingId
  if (form.source === 'example') return form.example.trim().length >= 3
  return form.description.trim().length >= 3
})

function stop() {
  if (timer) clearTimeout(timer)
  timer = null
}

async function poll() {
  stop()
  if (!subjectId.value || disposed) return
  try {
    state.value = await api<RuleState>('/api/ai/rules', { query: { subject_id: subjectId.value } })
    available.value = state.value.available
  }
  catch (err) {
    failure.value = errorMessage(err)
    return
  }
  if (pending.value && !disposed) {
    timer = setTimeout(poll, 2000)
    return
  }
  if (output.value && available.value && !verdict.value) await runTest()
}

async function generate() {
  if (!canGenerate.value) return
  stop()
  failure.value = ''
  verdict.value = null
  state.value = null
  requesting.value = true
  const body: Record<string, unknown> = { engine: form.engine, source: form.source, locale: locale.value }
  if (form.source === 'finding') body.finding_id = props.findingId
  if (form.source === 'example') body.example = form.example
  if (form.description.trim()) body.description = form.description.trim()
  if (/^[a-z][a-z0-9+#-]{0,31}$/.test(form.language.trim())) body.language = form.language.trim()
  try {
    const r = await api<{ subject_id: string | null }>('/api/ai/rules', { method: 'POST', body })
    subjectId.value = r.subject_id
    if (!r.subject_id) failure.value = t('ai.rulegen.notSent')
  }
  catch (err) {
    failure.value = errorMessage(err)
  }
  finally {
    requesting.value = false
  }
  await poll()
}

async function runTest() {
  if (!subjectId.value) return
  testing.value = true
  try {
    verdict.value = await api<Verdict>('/api/ai/rules/test', { method: 'POST', body: { subject_id: subjectId.value } })
  }
  catch (err) {
    failure.value = errorMessage(err)
  }
  finally {
    testing.value = false
  }
}

// ---- Enregistrement (administrateur, confirmé) ----
const saveOpen = ref(false)
const saving = ref(false)
const rulesets = ref<Ruleset[]>([])
const NEW = 'new'
const save = reactive({ target: NEW, slug: '', name: '' })
const rulesetItems = computed(() => [
  { label: t('ai.rulegen.newRuleset'), value: NEW },
  ...rulesets.value.map(r => ({ label: `${r.name} (${r.slug})`, value: r.id })),
])
const canSave = computed(() => save.target !== NEW || (/^[a-z0-9][a-z0-9-]{0,62}$/.test(save.slug) && save.name.trim().length > 0))

async function openSave() {
  const engine = state.value?.engine
  if (!engine) return
  try {
    rulesets.value = (await api<{ items: Ruleset[] }>('/api/ai/rules/rulesets', { query: { engine } })).items
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
    return
  }
  Object.assign(save, { target: NEW, slug: output.value?.rule_id.replace(/[^a-z0-9-]/g, '-').slice(0, 63) ?? '', name: '' })
  saveOpen.value = true
}

async function confirmSave() {
  if (!subjectId.value) return
  if (!canSave.value) {
    toast.add({ title: t('ai.rulegen.slugInvalid'), color: 'error' })
    return
  }
  saving.value = true
  try {
    const body: Record<string, unknown> = { subject_id: subjectId.value, confirmed: true }
    if (save.target === NEW) body.new_ruleset = { slug: save.slug, name: save.name.trim() }
    else body.ruleset_id = save.target
    const r = await api<{ version: number }>('/api/ai/rules/save', { method: 'POST', body })
    toast.add({ title: t('ai.rulegen.saved', { version: r.version }), color: 'success' })
    saveOpen.value = false
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

onMounted(async () => {
  try {
    const r = await api<RuleState>('/api/ai/rules')
    enabled.value = r.enabled
    available.value = r.available
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
    v-if="enabled && session.can('operator')"
    class="space-y-3 rounded-md border border-default p-3 text-sm"
    data-testid="ai-rulegen"
  >
    <h3 class="flex items-center gap-1 font-semibold">
      <UIcon name="i-lucide-wand-sparkles" />
      {{ t('ai.rulegen.title') }}
    </h3>

    <form
      class="grid gap-3 md:grid-cols-3"
      @submit.prevent="generate"
    >
      <UFormField :label="t('ai.rulegen.engine')">
        <USelect
          v-model="form.engine"
          :items="engineItems"
          class="w-full"
          data-testid="ai-rulegen-engine"
        />
      </UFormField>
      <UFormField :label="t('ai.rulegen.source')">
        <USelect
          v-model="form.source"
          :items="sourceItems"
          class="w-full"
        />
      </UFormField>
      <UFormField :label="t('ai.rulegen.language')">
        <UInput
          v-model="form.language"
          :maxlength="32"
          placeholder="python"
          class="w-full"
        />
      </UFormField>
      <UFormField
        :label="t('ai.rulegen.description')"
        class="md:col-span-3"
      >
        <UTextarea
          v-model="form.description"
          :maxlength="1000"
          :rows="2"
          class="w-full"
          data-testid="ai-rulegen-description"
        />
      </UFormField>
      <UFormField
        v-if="form.source === 'example'"
        :label="t('ai.rulegen.example')"
        class="md:col-span-3"
      >
        <UTextarea
          v-model="form.example"
          :maxlength="8000"
          :rows="6"
          class="w-full font-mono"
        />
      </UFormField>
      <div class="md:col-span-3">
        <UButton
          type="submit"
          size="sm"
          icon="i-lucide-sparkles"
          :loading="pending"
          :disabled="!canGenerate"
          :label="t('ai.rulegen.generate')"
          data-testid="ai-rulegen-generate"
        />
      </div>
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
      {{ t('ai.rulegen.pending') }}
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
      v-else-if="output"
      class="space-y-2"
      data-testid="ai-rulegen-result"
    >
      <div class="flex flex-wrap items-center gap-2">
        <code class="font-semibold">{{ output.rule_id }}</code>
        <UBadge
          v-if="mark"
          color="neutral"
          variant="subtle"
          :label="mark"
          data-testid="ai-mark"
        />
      </div>
      <p class="text-muted">
        {{ output.explanation }}
      </p>
      <pre class="max-h-80 overflow-auto rounded-md bg-elevated p-2 text-xs">{{ output.rule }}</pre>
      <div class="grid gap-2 md:grid-cols-2">
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.rulegen.positive', { file: output.positive.filename }) }}
          </h4>
          <pre class="max-h-48 overflow-auto rounded-md bg-elevated p-2 text-xs">{{ output.positive.content }}</pre>
        </div>
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.rulegen.negative', { file: output.negative.filename }) }}
          </h4>
          <pre class="max-h-48 overflow-auto rounded-md bg-elevated p-2 text-xs">{{ output.negative.content }}</pre>
        </div>
      </div>

      <p
        v-if="!available"
        class="text-muted"
      >
        {{ t('ai.rulegen.noRulesets') }}
      </p>
      <div
        v-else-if="testing"
        class="flex items-center gap-2 text-muted"
      >
        <UIcon
          name="i-lucide-loader-circle"
          class="animate-spin"
        />
        {{ t('ai.rulegen.testing') }}
      </div>
      <div
        v-else-if="verdict"
        class="space-y-1"
        data-testid="ai-rulegen-verdict"
      >
        <UBadge
          :color="verdict.passed ? 'success' : 'error'"
          variant="subtle"
          :label="verdict.passed ? t('ai.rulegen.testPassed') : t('ai.rulegen.testFailed')"
        />
        <p class="text-xs text-muted">
          {{ t('ai.rulegen.testCounts', { positive: verdict.positive_matches, negative: verdict.negative_matches }) }}
        </p>
        <ul
          v-if="verdict.errors.length"
          class="list-disc ps-5 text-xs text-muted"
        >
          <li
            v-for="(e, i) in verdict.errors"
            :key="i"
          >
            {{ e }}
          </li>
        </ul>
      </div>

      <div class="flex flex-wrap items-center gap-2">
        <UButton
          v-if="available && verdict"
          size="sm"
          variant="outline"
          icon="i-lucide-rotate-cw"
          :loading="testing"
          :label="t('ai.rulegen.retest')"
          @click="runTest"
        />
        <UButton
          v-if="session.can('admin') && verdict?.passed"
          size="sm"
          icon="i-lucide-save"
          :label="t('ai.rulegen.save')"
          data-testid="ai-rulegen-save"
          @click="openSave"
        />
        <span class="text-xs text-muted">{{ t('ai.rulegen.notSaved') }}</span>
      </div>
    </div>

    <ConfirmModal
      v-model:open="saveOpen"
      :title="t('ai.rulegen.saveTitle')"
      :body="t('ai.rulegen.saveBody')"
      :confirm-label="t('ai.rulegen.save')"
      :loading="saving"
      :ack="t('ai.rulegen.saveAck')"
      @confirm="confirmSave"
    >
      <UFormField :label="t('ai.rulegen.ruleset')">
        <USelect
          v-model="save.target"
          :items="rulesetItems"
          class="w-full"
        />
      </UFormField>
      <template v-if="save.target === NEW">
        <UFormField :label="t('ai.rulegen.slug')">
          <UInput
            v-model="save.slug"
            :maxlength="63"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('ai.rulegen.name')">
          <UInput
            v-model="save.name"
            :maxlength="200"
            class="w-full"
          />
        </UFormField>
      </template>
    </ConfirmModal>
  </section>
</template>
