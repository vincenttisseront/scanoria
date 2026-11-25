<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Système › Intelligence artificielle (CLAUDE.md § 3.5, I1, I23) : une seule
saisie obligatoire (l'adresse du serveur Ollama), un serveur candidat proposé,
une seule confirmation (modale d'activation : ce qui part, vers qui, ce qui ne
part jamais), puis tout est automatique : modèles par tâche et pourquoi, banc
d'essai, disjoncteur, latence, journal des appels.
-->

<script setup lang="ts">
interface ModelChoice { model: string, digest: string, reason: string }
interface TaskState {
  kind: string
  /** I7 : modèle d'embedding, choisi automatiquement. */
  embedding?: boolean
  model: ModelChoice | null
  override: string | null
  testbed: { score: number, threshold: number, passed: boolean, at: string } | null
  threshold: number | null
  state: 'off' | 'no-model' | 'testing' | 'active' | 'disabled'
}
interface AiStatusResponse {
  enabled: boolean
  endpoint: { url: string | null, host: string | null, port: number | null, addresses: string[], insecure: boolean, token: boolean, ca: boolean, tls_verify: boolean, pinned_at: string | null }
  token_stored: boolean
  token_supported: boolean
  check: {
    checked_at: string
    resolution: { pinned: string[], current: string[], changed: boolean, error: string | null } | null
    candidate: { url: string, version: string, addresses: string[], insecure: boolean } | null
  } | null
  probe: { status: string, error: string | null, at: string | null, version: string | null, pending?: boolean, stalled?: boolean } | null
  models: { name: string, capabilities: string[], parameters_b?: number | null, context?: number | null }[]
  models_at?: string | null
  embedding: { model: string, reason: string } | null
  defaults?: { generation: string | null, embedding: string | null }
  tasks: TaskState[]
  circuit: { state: 'open' | 'closed', last_failure_at: string | null }
  latency_ms: number | null
  queue: { queued: number, running: number }
}
interface AgreementRow { kind: string, model: string | null, votes: number, up: number, rate: number | null, triaged: number | null, matched: number | null, triage_rate: number | null }
interface CallRow { id: number, kind: string, model: string | null, bytes_sent: number, duration_ms: number | null, outcome: string, at: string, project: string | null }

const URL_RE = /^https?:\/\/(\[[0-9a-f:.]{2,45}\]|[a-z0-9.-]{1,253})(:[0-9]{1,5})?\/?$/

definePageMeta({ role: 'operator' })

const { t, te } = useI18n()
useHead({ title: computed(() => t('ai.title')) })

const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const { api, errorMessage } = useApi()
const toast = useToast()

const info = ref<AiStatusResponse | null>(null)
const calls = ref<CallRow[]>([])
const agreementRows = ref<AgreementRow[]>([])
const loading = ref(false)

async function refresh(quiet = false) {
  if (!quiet) loading.value = true
  try {
    const [s, c, a] = await Promise.all([
      api<AiStatusResponse>('/api/ai/status'),
      api<{ calls: CallRow[] }>('/api/ai/calls'),
      api<{ items: AgreementRow[] }>('/api/ai/agreement').catch(() => ({ items: [] as AgreementRow[] })),
    ])
    info.value = s
    calls.value = c.calls
    agreementRows.value = a.items
    // Le formulaire n'est prérempli qu'au chargement, jamais par le suivi périodique.
    if (!quiet && !form.url && s.endpoint.url) form.url = s.endpoint.url
    if (!quiet && s.endpoint.insecure) form.insecure = true
    if (!quiet && s.endpoint.url && !s.endpoint.tls_verify) form.skipVerify = true
  }
  catch (err) {
    if (!quiet) toast.add({ title: errorMessage(err), color: 'error', icon: 'i-lucide-circle-x' })
  }
  finally {
    if (!quiet) loading.value = false
  }
}
// Santé du connecteur (disjoncteur, file, latence) et journal des appels suivis
// en continu : sans cela, la page restait figée jusqu'à la prochaine action.
let poll: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void refresh()
  poll = setInterval(() => void refresh(true), 15_000)
})
onBeforeUnmount(() => {
  if (poll) clearInterval(poll)
})

// --- Connecteur ---
const form = reactive({ url: '', insecure: false, token: '', removeToken: false, ca: '', skipVerify: false })
const isHttp = computed(() => form.url.trim().startsWith('http:'))
/** Vérification du certificat désactivée : https seulement, et l'AC fournie n'a alors plus d'usage. */
const skipVerify = computed(() => !isHttp.value && form.skipVerify)
const urlValid = computed(() => URL_RE.test(form.url.trim().toLowerCase()))
const formValid = computed(() => urlValid.value
  && (!isHttp.value || form.insecure)
  && !(isHttp.value && form.token.trim())
  && (skipVerify.value || !form.ca.trim() || form.ca.trim().startsWith('-----BEGIN CERTIFICATE-----')))

function pickCandidate() {
  const c = info.value?.check?.candidate
  if (!c) return
  form.url = c.url
  form.insecure = c.insecure
}

const activateModal = ref(false)
const connectReq = useHelperRequest()
const connectParams = computed(() => {
  const body: Record<string, unknown> = { url: form.url.trim().replace(/\/$/, ''), confirmed: true }
  if (isHttp.value) body.allow_insecure = true
  if (form.token.trim()) body.token = form.token.trim()
  else if (form.removeToken) body.token = null
  if (skipVerify.value) body.skip_tls_verify = true
  else if (form.ca.trim()) body.ca_pem = `${form.ca.trim()}\n`
  return body
})
async function connect() {
  const r = await connectReq.run('/api/ai/connector', connectParams.value)
  activateModal.value = false
  form.token = ''
  form.removeToken = false
  if (r) await refresh()
}

function openActivation() {
  activateModal.value = true
}

function reconfirm() {
  if (info.value?.endpoint.url) form.url = info.value.endpoint.url
  activateModal.value = true
}

const removeModal = ref(false)
function openRemoval() {
  removeModal.value = true
}
const removeReq = useHelperRequest()
async function disconnect() {
  const r = await removeReq.run('/api/ai/disconnect', {})
  removeModal.value = false
  if (r) await refresh()
}

// --- Modèles ---
// La découverte est faite par scanoria-ai (seul à pouvoir déchiffrer le jeton et
// joindre le serveur) : la console dépose la demande puis suit l'état jusqu'à
// la fin, avec un indicateur d'attente.
const probing = ref(false)
const PROBE_POLL_MS = 1500
const PROBE_POLL_MAX = 40
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
async function waitProbe() {
  for (let i = 0; i < PROBE_POLL_MAX && info.value?.probe?.pending && !info.value.probe.stalled; i++) {
    await sleep(PROBE_POLL_MS)
    await refresh(true)
  }
}
async function rediscover() {
  probing.value = true
  try {
    await api('/api/ai/probe', { method: 'POST', body: {} })
    await refresh(true)
    await waitProbe()
    const p = info.value?.probe
    if (p?.stalled) toast.add({ title: t('ai.models.stalled'), color: 'warning', icon: 'i-lucide-triangle-alert' })
    else if (p?.pending) toast.add({ title: t('ai.models.stillRunning'), color: 'info', icon: 'i-lucide-loader' })
    else if (p?.status === 'error') toast.add({ title: t('ai.models.unreachable', { cause: outcomeLabel(p.error ?? 'error') }), color: 'error', icon: 'i-lucide-circle-x' })
    else toast.add({ title: t('ai.models.discovered', { n: info.value?.models.length ?? 0 }), color: 'success', icon: 'i-lucide-circle-check' })
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error', icon: 'i-lucide-circle-x' })
  }
  finally {
    probing.value = false
  }
}
// Demande en attente depuis plus de deux minutes : scanoria-ai ne la traite pas.
const probeStalled = computed(() => !!info.value?.probe?.stalled)
const probeBusy = computed(() => probing.value || (!!info.value?.probe?.pending && !probeStalled.value))
const probeFailed = computed(() => !probeBusy.value && info.value?.probe?.status === 'error')

const AUTO = '__auto__'
const OTHER = '__other__'
const MODEL_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/
const savingKind = ref<string | null>(null)
type ModelRow = AiStatusResponse['models'][number]
const completionList = computed(() => (info.value?.models ?? []).filter(m => m.capabilities.includes('completion')))
const embeddingList = computed(() => (info.value?.models ?? []).filter(m => m.capabilities.includes('embedding')))
const completionModels = computed(() => completionList.value.map(m => m.name))
function modelLabel(m: ModelRow) {
  const parts = [m.name]
  if (typeof m.parameters_b === 'number') parts.push(m.parameters_b >= 1 ? `${Math.round(m.parameters_b * 10) / 10} B` : `${Math.round(m.parameters_b * 1000)} M`)
  if (typeof m.context === 'number') parts.push(m.context >= 1024 ? t('ai.models.contextK', { k: Math.round(m.context / 1024) }) : t('ai.models.contextTokens', { n: m.context }))
  return parts.join(' · ')
}
/** Éléments d'une liste : automatique, modèles du serveur, choix actuel absent du serveur, saisie libre. */
function pickerItems(list: ModelRow[], current: string | null, autoLabel: string, withOther = true) {
  const items = [{ label: autoLabel, value: AUTO }]
  for (const m of [...list].sort((a, b) => a.name.localeCompare(b.name))) items.push({ label: modelLabel(m), value: m.name })
  if (current && !list.some(m => m.name === current)) items.push({ label: t('ai.models.missing', { name: current }), value: current })
  if (withOther) items.push({ label: t('ai.models.other'), value: OTHER })
  return items
}
const generationItems = computed(() => pickerItems(completionList.value, info.value?.defaults?.generation ?? null, t('ai.models.automatic')))
const embeddingItems = computed(() => pickerItems(embeddingList.value, info.value?.defaults?.embedding ?? null, t('ai.models.automatic')))
function modelItems(task: TaskState) {
  const autoLabel = info.value?.defaults?.generation ? t('ai.models.sameAsDefault') : t('ai.models.automatic')
  return pickerItems(completionList.value, task.override, autoLabel, false)
}

/** Saisie libre de secours (liste vide ou serveur injoignable) : « default » ou « embedding ». */
const custom = reactive<Record<'default' | 'embedding', { open: boolean, value: string }>>({
  default: { open: false, value: '' },
  embedding: { open: false, value: '' },
})
const customOpen = (key: 'default' | 'embedding') => custom[key].open
const customValue = (key: 'default' | 'embedding') => custom[key].value
function setCustom(key: 'default' | 'embedding', v: string | number | null | undefined) {
  custom[key].value = v == null ? '' : String(v)
}
const customValid = (key: 'default' | 'embedding') => MODEL_NAME_RE.test(custom[key].value.trim())
function pickGlobal(key: 'default' | 'embedding', value: string) {
  if (value === OTHER) {
    custom[key].open = true
    custom[key].value = ''
    return
  }
  custom[key].open = false
  void setOverride(key, value)
}
async function saveCustom(key: 'default' | 'embedding') {
  if (!customValid(key)) return
  if (await setOverride(key, custom[key].value.trim())) custom[key].open = false
}

async function setOverride(kind: string, value: string): Promise<boolean> {
  savingKind.value = kind
  try {
    await api('/api/ai/models', { method: 'PUT', body: { models: { [kind]: value === AUTO ? null : value } } })
    toast.add({ title: t('ai.models.saved'), color: 'success', icon: 'i-lucide-circle-check' })
    await refresh(true)
    void waitProbe()
    return true
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error', icon: 'i-lucide-circle-x' })
    return false
  }
  finally {
    savingKind.value = null
  }
}

function kindLabel(kind: string) {
  return te(`ai.kinds.${kind}`) ? t(`ai.kinds.${kind}`) : kind
}
function reasonLabel(reason: string | undefined) {
  return reason && te(`ai.reasons.${reason}`) ? t(`ai.reasons.${reason}`) : (reason ?? '—')
}
function outcomeLabel(outcome: string) {
  return te(`ai.errors.${outcome}`) ? t(`ai.errors.${outcome}`) : outcome
}
const STATE_COLOR: Record<TaskState['state'], 'neutral' | 'warning' | 'info' | 'success' | 'error'> = {
  'off': 'neutral', 'no-model': 'warning', 'testing': 'info', 'active': 'success', 'disabled': 'error',
}
const stateColor = (state: TaskState['state']) => STATE_COLOR[state]
const connecting = computed(() => connectReq.running.value)
const connectLabel = computed(() => connectReq.label.value)
const removing = computed(() => removeReq.running.value)
const removeLabel = computed(() => removeReq.label.value)
const formatDate = (iso: string | null | undefined) => fmt.date(iso)
const resolution = computed(() => info.value?.check?.resolution ?? null)
</script>

<template>
  <PageShell :title="t('ai.title')">
    <p class="text-sm text-muted">
      {{ t('ai.intro') }}
    </p>

    <div
      v-if="loading && !info"
      class="flex items-center gap-2 text-sm text-muted"
      data-testid="ai-loading"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="info">
      <UAlert
        v-if="info.enabled && resolution?.changed"
        color="warning"
        icon="i-lucide-triangle-alert"
        :title="t('ai.connector.resolutionChanged', { addresses: resolution.current.join(', ') })"
      >
        <template
          v-if="isAdmin"
          #actions
        >
          <UButton
            size="sm"
            :label="t('ai.connector.reconfirm')"
            @click="reconfirm"
          />
        </template>
      </UAlert>
      <UAlert
        v-else-if="info.enabled && resolution?.error"
        color="warning"
        icon="i-lucide-triangle-alert"
        :title="t('ai.connector.resolutionError', { code: resolution.error })"
      />

      <UCard>
        <template #header>
          <div class="flex items-center justify-between gap-2">
            <h2 class="font-semibold">
              {{ t('ai.connector.title') }}
            </h2>
            <UBadge
              :color="info.enabled ? 'success' : 'neutral'"
              variant="subtle"
              :label="info.enabled ? t('ai.connector.active') : t('ai.connector.inactive')"
            />
          </div>
        </template>

        <dl
          v-if="info.enabled"
          class="mb-4 grid gap-2 text-sm md:grid-cols-[max-content_1fr] md:gap-x-6"
        >
          <dt class="text-muted">
            {{ t('ai.connector.url') }}
          </dt>
          <dd class="font-mono break-all">
            {{ info.endpoint.url }}
          </dd>
          <dt class="text-muted">
            {{ t('ai.connector.pinned') }}
          </dt>
          <dd>
            <span class="font-mono">{{ info.endpoint.addresses.join(', ') }}</span>
            <span class="block text-xs text-muted">{{ t('ai.connector.pinnedHelp') }}</span>
          </dd>
          <dt class="text-muted">
            {{ t('ai.connector.pinnedAt') }}
          </dt>
          <dd>{{ formatDate(info.endpoint.pinned_at) }}</dd>
          <template v-if="info.endpoint.token || info.endpoint.ca || !info.endpoint.tls_verify">
            <dt class="text-muted">
              {{ t('ai.connector.options') }}
            </dt>
            <dd>
              {{ [info.endpoint.token ? t('ai.connector.withToken') : '', info.endpoint.ca ? t('ai.connector.withCa') : ''].filter(Boolean).join(', ') }}
              <UBadge
                v-if="!info.endpoint.tls_verify"
                color="warning"
                variant="subtle"
                icon="i-lucide-shield-alert"
                :label="t('ai.connector.noVerify')"
                data-testid="ai-no-verify"
              />
            </dd>
          </template>
        </dl>

        <UAlert
          v-if="isAdmin && info.check?.candidate && form.url.trim() !== info.check.candidate.url"
          class="mb-4"
          color="info"
          icon="i-lucide-sparkles"
          :title="t('ai.connector.candidate', { url: info.check.candidate.url, version: info.check.candidate.version })"
        >
          <template #actions>
            <UButton
              size="sm"
              variant="outline"
              :label="t('ai.connector.useCandidate')"
              @click="pickCandidate"
            />
          </template>
        </UAlert>

        <div
          v-if="isAdmin"
          class="space-y-4"
        >
          <UFormField
            :label="t('ai.connector.url')"
            :help="t('ai.connector.urlHelp')"
            required
          >
            <UInput
              v-model="form.url"
              class="w-full font-mono"
              placeholder="https://ollama.exemple.test:11434"
              data-testid="ai-url"
            />
          </UFormField>
          <div v-if="isHttp">
            <UCheckbox
              v-model="form.insecure"
              :label="t('ai.connector.insecure')"
            />
            <p class="mt-1 text-xs text-warning">
              {{ t('ai.connector.insecureWarning') }}
            </p>
          </div>
          <UFormField
            :label="t('ai.connector.token')"
            :help="info.token_supported ? (info.token_stored ? t('ai.connector.tokenStored') : t('ai.connector.tokenHelp')) : t('ai.connector.tokenUnsupported')"
          >
            <UInput
              v-model="form.token"
              type="password"
              autocomplete="off"
              class="w-full"
              :disabled="!info.token_supported || isHttp"
            />
          </UFormField>
          <UCheckbox
            v-if="info.token_stored"
            v-model="form.removeToken"
            :label="t('ai.connector.tokenRemove')"
          />
          <div v-if="!isHttp">
            <UCheckbox
              v-model="form.skipVerify"
              :label="t('ai.connector.skipVerify')"
              data-testid="ai-skip-verify"
            />
            <p
              v-if="form.skipVerify"
              class="mt-1 text-xs text-warning"
            >
              {{ t('ai.connector.skipVerifyWarning') }}
            </p>
            <p
              v-else
              class="mt-1 text-xs text-muted"
            >
              {{ t('ai.connector.skipVerifyHelp') }}
            </p>
          </div>
          <UFormField
            :label="t('ai.connector.ca')"
            :help="skipVerify ? t('ai.connector.caIgnored') : undefined"
          >
            <UTextarea
              v-model="form.ca"
              :rows="3"
              class="w-full font-mono text-xs"
              :disabled="skipVerify"
            />
          </UFormField>
          <div class="flex flex-wrap items-center gap-3">
            <UButton
              icon="i-lucide-plug"
              :disabled="!formValid || connecting"
              :loading="connecting"
              :label="info.enabled ? t('ai.connector.update') : t('ai.connector.enable')"
              @click="openActivation"
            />
            <UButton
              v-if="info.enabled"
              icon="i-lucide-unplug"
              color="error"
              variant="outline"
              :loading="removing"
              :label="t('ai.connector.remove')"
              @click="openRemoval"
            />
            <RequestProgress
              :active="connecting"
              :label="connectLabel"
            />
            <RequestProgress
              :active="removing"
              :label="removeLabel"
            />
          </div>
        </div>
      </UCard>
    </template>

    <!-- Bloc distinct : les v-model du formulaire font perdre au contrôle de types le rétrécissement de « info ». -->
    <template v-if="info">
      <UCard v-if="info.enabled">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 class="font-semibold">
                {{ t('ai.models.title') }}
              </h2>
              <p class="text-sm text-muted">
                {{ t('ai.models.help') }}
              </p>
            </div>
            <UButton
              v-if="isAdmin"
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="outline"
              :loading="probeBusy"
              :disabled="probeBusy"
              :label="t('ai.models.rediscover')"
              data-testid="ai-rediscover"
              @click="rediscover"
            />
          </div>
        </template>
        <p
          v-if="probeBusy"
          class="mb-3 flex items-center gap-2 text-sm text-muted"
          data-testid="ai-probe-pending"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-4 animate-spin"
          />
          {{ t('ai.models.discovering') }}
        </p>
        <UAlert
          v-else-if="probeStalled"
          class="mb-3"
          color="warning"
          variant="subtle"
          icon="i-lucide-triangle-alert"
          data-testid="ai-probe-stalled"
          :title="t('ai.models.stalled')"
        />
        <UAlert
          v-else-if="probeFailed"
          class="mb-3"
          color="error"
          variant="subtle"
          icon="i-lucide-server-off"
          data-testid="ai-probe-error"
          :title="t('ai.models.unreachable', { cause: outcomeLabel(info.probe?.error ?? 'error') })"
          :description="info.models_at ? t('ai.models.lastKnown', { at: formatDate(info.models_at) }) : t('ai.models.typeName')"
        />
        <p
          v-else-if="!completionModels.length && info.probe"
          class="mb-3 text-sm text-warning"
        >
          {{ t('ai.models.none') }}
        </p>

        <!-- Cas courant : un modèle de rédaction pour toutes les tâches, un modèle d'embedding. -->
        <div
          class="mb-4 grid gap-4 sm:grid-cols-2"
          data-testid="ai-model-pickers"
        >
          <div
            v-for="which in (['default', 'embedding'] as const)"
            :key="which"
            :data-testid="`ai-pick-${which}`"
          >
            <p class="mb-1 text-sm font-medium">
              {{ t(which === 'default' ? 'ai.models.generation' : 'ai.models.embedding') }}
            </p>
            <template v-if="isAdmin">
              <USelect
                :model-value="(which === 'default' ? info.defaults?.generation : info.defaults?.embedding) ?? AUTO"
                :items="which === 'default' ? generationItems : embeddingItems"
                :loading="savingKind === which"
                :disabled="savingKind === which"
                class="w-full"
                @update:model-value="pickGlobal(which, $event)"
              />
              <div
                v-if="customOpen(which)"
                class="mt-2 flex gap-2"
              >
                <UInput
                  :model-value="customValue(which)"
                  :placeholder="which === 'default' ? 'qwen2.5-coder:14b' : 'nomic-embed-text'"
                  class="flex-1 font-mono"
                  :data-testid="`ai-custom-${which}`"
                  @update:model-value="setCustom(which, $event)"
                  @keydown.enter="saveCustom(which)"
                />
                <UButton
                  :label="t('ai.models.use')"
                  :disabled="!customValid(which)"
                  :loading="savingKind === which"
                  @click="saveCustom(which)"
                />
              </div>
            </template>
            <p
              v-else
              class="font-mono text-sm"
            >
              {{ (which === 'default' ? info.defaults?.generation : info.defaults?.embedding) ?? t('ai.models.automatic') }}
            </p>
          </div>
        </div>
        <p
          v-if="isAdmin"
          class="mb-2 text-sm text-muted"
        >
          {{ t('ai.models.perTask') }}
        </p>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="text-left text-muted">
              <tr>
                <th class="py-1 pr-4">
                  {{ t('ai.models.task') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.models.model') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.models.why') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.models.testbed') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.models.state') }}
                </th>
                <th
                  v-if="isAdmin"
                  class="py-1"
                >
                  {{ t('ai.models.choice') }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="task in info.tasks"
                :key="task.kind"
                class="border-t border-default"
                :data-testid="`ai-task-${task.kind}`"
              >
                <td class="py-2 pr-4">
                  {{ kindLabel(task.kind) }}
                </td>
                <td class="py-2 pr-4 font-mono">
                  {{ task.model?.model ?? '—' }}
                </td>
                <td class="py-2 pr-4">
                  {{ reasonLabel(task.model?.reason) }}
                </td>
                <td class="py-2 pr-4">
                  {{ task.testbed ? t('ai.models.score', { score: Math.round(task.testbed.score * 100), threshold: Math.round(task.testbed.threshold * 100) }) : '—' }}
                </td>
                <td class="py-2 pr-4">
                  <UBadge
                    :color="stateColor(task.state)"
                    variant="subtle"
                    :label="t(`ai.states.${task.state}`)"
                  />
                </td>
                <td
                  v-if="isAdmin"
                  class="py-2"
                >
                  <span
                    v-if="task.embedding"
                    class="text-xs text-muted"
                  >{{ t('ai.models.embeddingAbove') }}</span>
                  <USelect
                    v-else
                    :model-value="task.override ?? AUTO"
                    :items="modelItems(task)"
                    :loading="savingKind === task.kind"
                    class="min-w-48"
                    @update:model-value="setOverride(task.kind, $event)"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-4 text-sm">
          <span class="text-muted">{{ t('ai.models.embedding') }} : </span>
          <span v-if="info.embedding"><span class="font-mono">{{ info.embedding.model }}</span> ({{ reasonLabel(info.embedding.reason) }})</span>
          <span v-else>{{ t('ai.models.noEmbedding') }} {{ t('ai.models.noEmbeddingSimilar') }}</span>
        </p>
      </UCard>

      <UCard
        v-if="info.enabled"
        data-testid="ai-agreement"
      >
        <template #header>
          <h2 class="font-semibold">
            {{ t('ai.agreement.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('ai.agreement.help') }}
          </p>
        </template>
        <p
          v-if="!agreementRows.length"
          class="text-sm text-muted"
        >
          {{ t('ai.agreement.empty') }}
        </p>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="w-full text-sm">
            <thead class="text-left text-muted">
              <tr>
                <th class="py-1 pr-4">
                  {{ t('ai.agreement.task') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.agreement.model') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.agreement.votes') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.agreement.rate') }}
                </th>
                <th class="py-1">
                  {{ t('ai.agreement.triage') }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="r in agreementRows"
                :key="`${r.kind}:${r.model ?? ''}`"
                class="border-t border-default"
              >
                <td class="py-2 pr-4">
                  {{ kindLabel(r.kind) }}
                </td>
                <td class="py-2 pr-4 font-mono">
                  {{ r.model ?? '—' }}
                </td>
                <td class="py-2 pr-4">
                  {{ r.votes }}
                </td>
                <td class="py-2 pr-4">
                  {{ r.rate === null ? '—' : `${Math.round(r.rate * 100)} %` }}
                </td>
                <td class="py-2">
                  {{ r.triage_rate === null ? '—' : t('ai.agreement.triageValue', { rate: Math.round(r.triage_rate * 100), matched: r.matched ?? 0, total: r.triaged ?? 0 }) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </UCard>

      <UCard v-if="info.enabled">
        <template #header>
          <h2 class="font-semibold">
            {{ t('ai.health.title') }}
          </h2>
        </template>
        <dl class="grid gap-2 text-sm md:grid-cols-[max-content_1fr] md:gap-x-6">
          <dt class="text-muted">
            {{ t('ai.health.version') }}
          </dt>
          <dd>{{ info.probe?.version ?? '—' }}</dd>
          <dt class="text-muted">
            {{ t('ai.health.probe') }}
          </dt>
          <dd>
            {{ info.probe?.at ? formatDate(info.probe.at) : t('ai.health.never') }}
            <span
              v-if="info.probe?.status === 'error' && info.probe.error"
              class="text-error"
            > ({{ outcomeLabel(info.probe.error) }})</span>
          </dd>
          <dt class="text-muted">
            {{ t('ai.health.latency') }}
          </dt>
          <dd>{{ info.latency_ms === null ? '—' : `${info.latency_ms} ms` }}</dd>
          <dt class="text-muted">
            {{ t('ai.health.circuit') }}
          </dt>
          <dd :class="info.circuit.state === 'open' ? 'text-error' : ''">
            {{ info.circuit.state === 'open' ? t('ai.health.circuitOpen') : t('ai.health.circuitClosed') }}
          </dd>
          <dt class="text-muted">
            {{ t('ai.health.queue') }}
          </dt>
          <dd>{{ t('ai.health.queueValue', info.queue) }}</dd>
        </dl>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('ai.calls.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('ai.calls.help') }}
          </p>
        </template>
        <p
          v-if="!calls.length"
          class="text-sm text-muted"
        >
          {{ t('ai.calls.empty') }}
        </p>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="w-full text-sm">
            <thead class="text-left text-muted">
              <tr>
                <th class="py-1 pr-4">
                  {{ t('ai.calls.at') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.calls.kind') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.calls.project') }}
                </th>
                <th class="py-1 pr-4">
                  {{ t('ai.calls.model') }}
                </th>
                <th class="py-1 pr-4 text-right">
                  {{ t('ai.calls.bytes') }}
                </th>
                <th class="py-1 pr-4 text-right">
                  {{ t('ai.calls.duration') }}
                </th>
                <th class="py-1">
                  {{ t('ai.calls.outcome') }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="c in calls"
                :key="c.id"
                class="border-t border-default"
              >
                <td class="py-1 pr-4">
                  {{ formatDate(c.at) }}
                </td>
                <td class="py-1 pr-4">
                  {{ kindLabel(c.kind) }}
                </td>
                <td class="py-1 pr-4">
                  {{ c.project ?? '—' }}
                </td>
                <td class="py-1 pr-4 font-mono">
                  {{ c.model ?? '—' }}
                </td>
                <td class="py-1 pr-4 text-right">
                  {{ c.bytes_sent }}
                </td>
                <td class="py-1 pr-4 text-right">
                  {{ c.duration_ms === null ? '—' : `${c.duration_ms} ms` }}
                </td>
                <td class="py-1">
                  {{ c.outcome === 'ok' ? 'ok' : outcomeLabel(c.outcome) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </UCard>
    </template>

    <ConfirmModal
      v-model:open="activateModal"
      :title="t('ai.activation.title')"
      :body="t('ai.activation.intro', { url: connectParams.url })"
      :ack="t('ai.activation.ack')"
      :confirm-label="t('ai.activation.confirm')"
      color="warning"
      :loading="connecting"
      @confirm="connect"
    >
      <div class="space-y-3 text-sm">
        <div>
          <p class="font-medium">
            {{ t('ai.activation.sentTitle') }}
          </p>
          <ul class="list-disc pl-5">
            <li>{{ t('ai.activation.sent1') }}</li>
            <li>{{ t('ai.activation.sent2') }}</li>
            <li>{{ t('ai.activation.sent4') }}</li>
            <li>{{ t('ai.activation.sent5') }}</li>
            <li>{{ t('ai.activation.sent6') }}</li>
            <li>{{ t('ai.activation.sent7') }}</li>
            <li>{{ t('ai.activation.sent8') }}</li>
            <li>{{ t('ai.activation.sent9') }}</li>
            <li>{{ t('ai.activation.sent3') }}</li>
          </ul>
        </div>
        <div>
          <p class="font-medium">
            {{ t('ai.activation.neverTitle') }}
          </p>
          <ul class="list-disc pl-5">
            <li>{{ t('ai.activation.never1') }}</li>
            <li>{{ t('ai.activation.never2') }}</li>
            <li>{{ t('ai.activation.never3') }}</li>
          </ul>
        </div>
        <p class="text-muted">
          {{ t('ai.activation.how') }}
        </p>
        <p
          v-if="isHttp"
          class="text-warning"
        >
          {{ t('ai.connector.insecureWarning') }}
        </p>
        <p
          v-if="skipVerify"
          class="text-warning"
        >
          {{ t('ai.connector.skipVerifyWarning') }}
        </p>
      </div>
    </ConfirmModal>

    <ConfirmModal
      v-model:open="removeModal"
      :title="t('ai.connector.removeTitle')"
      :body="t('ai.connector.removeBody')"
      :confirm-label="t('ai.connector.remove')"
      color="error"
      :loading="removing"
      @confirm="disconnect"
    />
  </PageShell>
</template>
