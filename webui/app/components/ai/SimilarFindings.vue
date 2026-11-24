<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Résultats semblables d'un résultat (I7) : regroupés par embeddings, dans le
même projet, affichés à côté du recoupement exact (F16) sans le remplacer et
sans entrer dans le quality gate. Le groupe propose un tri commun : une
personne qui a le rôle opérateur choisit le statut, puis chaque résultat est
trié par l'API normale (POST /api/findings/:id/status), un par un, avec sa
ligne d'audit. Sans modèle d'embedding, la fonction est masquée et le dit.
Rien n'est affiché sans connecteur ni pour un projet « aucun envoi à l'IA ».
-->

<script setup lang="ts">
interface Item { id: string, score: number, title: string, tool: string, rule_id: string, severity: string, status: string, path: string | null, start_line: number | null }
interface SimilarResponse {
  enabled: boolean
  state: 'off' | 'opt-out' | 'no-embedding-model' | 'testing' | 'disabled-by-testbed' | 'pending' | 'ready'
  model: string | null
  model_digest: string | null
  threshold: number | null
  items: Item[]
}

const props = withDefaults(defineProps<{ findingId: string, pollMs?: number }>(), { pollMs: 3000 })
const emit = defineEmits<{ triaged: [], open: [id: string] }>()
const { t } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const session = useSession()
const canTriage = computed(() => session.can('operator'))

const data = ref<SimilarResponse | null>(null)
const selected = ref<string[]>([])
let timer: ReturnType<typeof setTimeout> | null = null
let disposed = false
// Une seule lecture prise en compte (la dernière) ; relances espacées puis arrêtées.
let seq = 0
let polls = 0
const MAX_POLLS = 20

const visible = computed(() => !!data.value?.enabled && data.value.state !== 'off' && data.value.state !== 'opt-out')
const mark = computed(() => (data.value?.model ? t('ai.explain.mark', { model: `${data.value.model}${data.value.model_digest ? ` (${data.value.model_digest.slice(0, 12)})` : ''}` }) : ''))

async function load() {
  if (timer) clearTimeout(timer)
  timer = null
  const mine = ++seq
  let next: SimilarResponse | null
  try {
    next = await api<SimilarResponse>('/api/ai/similar', { query: { finding_id: props.findingId } })
  }
  catch {
    next = null
  }
  if (mine !== seq || disposed) return
  data.value = next
  selected.value = selected.value.filter(id => data.value?.items.some(i => i.id === id))
  if (data.value?.state === 'pending' && polls < MAX_POLLS) {
    timer = setTimeout(load, Math.min(30_000, props.pollMs * 1.5 ** polls))
    polls++
  }
}
function reload() {
  polls = 0
  void load()
}
watch(() => props.findingId, () => {
  selected.value = []
  reload()
})
onMounted(reload)
onBeforeUnmount(() => {
  disposed = true
  if (timer) clearTimeout(timer)
})

function toggle(id: string, on: boolean | 'indeterminate') {
  selected.value = on === true ? [...new Set([...selected.value, id])] : selected.value.filter(x => x !== id)
}

// Tri commun : confirmé par une personne, appliqué résultat par résultat.
const open = ref(false)
const applying = ref(false)
const form = reactive<{ status: 'confirmed' | 'false-positive' | 'accepted', reason: string, until: string }>({ status: 'confirmed', reason: '', until: '' })
const statusItems = computed(() => (['confirmed', 'false-positive', 'accepted'] as const).map(s => ({ label: t(`findings.status.${s}`), value: s })))
const needsReason = computed(() => form.status !== 'confirmed')
const formValid = computed(() => (!needsReason.value || form.reason.trim().length >= 3) && (form.status !== 'accepted' || /^\d{4}-\d{2}-\d{2}$/.test(form.until)))

function body(): Record<string, unknown> {
  if (form.status === 'confirmed') return { status: 'confirmed', ...(form.reason.trim() ? { reason: form.reason.trim() } : {}) }
  if (form.status === 'false-positive') return { status: 'false-positive', reason: form.reason.trim() }
  return { status: 'accepted', reason: form.reason.trim(), until: form.until }
}

async function apply() {
  if (!formValid.value) {
    toast.add({ title: t('ai.similar.invalid'), color: 'error' })
    return
  }
  applying.value = true
  const ids = [...selected.value]
  let ok = 0
  try {
    for (const id of ids) {
      try {
        await api(`/api/findings/${id}/status`, { method: 'POST', body: body() })
        ok++
      }
      catch (err) {
        toast.add({ title: errorMessage(err), color: 'error' })
      }
    }
  }
  finally {
    applying.value = false
  }
  open.value = false
  toast.add({ title: t('ai.similar.applied', { ok, count: ids.length }), color: ok === ids.length ? 'success' : 'warning' })
  if (ok < ids.length) toast.add({ title: t('ai.similar.partial', { failed: ids.length - ok }), color: 'warning' })
  selected.value = []
  emit('triaged')
  polls = 0
  await load()
}
</script>

<template>
  <section
    v-if="visible && data"
    class="space-y-2 rounded-md border border-default p-3 text-sm"
    data-testid="ai-similar"
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="flex items-center gap-1 font-semibold">
        <UIcon name="i-lucide-group" />
        {{ t('ai.similar.title') }}
      </h3>
      <UBadge
        v-if="mark && data.state === 'ready' && data.items.length"
        color="neutral"
        variant="subtle"
        :label="mark"
        data-testid="ai-mark"
      />
    </div>

    <p
      v-if="data.state === 'no-embedding-model' || data.state === 'testing' || data.state === 'disabled-by-testbed'"
      class="text-muted"
      :data-testid="`ai-similar-${data.state}`"
    >
      {{ t(`ai.similar.states.${data.state}`) }}
    </p>

    <div
      v-else-if="data.state === 'pending'"
      class="flex items-center gap-2 text-muted"
      data-testid="ai-pending"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('ai.similar.pending') }}
    </div>

    <template v-else>
      <p
        v-if="!data.items.length"
        class="text-muted"
      >
        {{ t('ai.similar.none') }}
      </p>
      <ul
        v-else
        class="space-y-1"
      >
        <li
          v-for="item in data.items"
          :key="item.id"
          class="flex items-start gap-2"
          :data-testid="`ai-similar-item-${item.id}`"
        >
          <UCheckbox
            v-if="canTriage"
            :model-value="selected.includes(item.id)"
            :aria-label="t('ai.similar.select')"
            @update:model-value="toggle(item.id, $event)"
          />
          <div class="min-w-0 flex-1">
            <button
              type="button"
              class="text-left hover:underline"
              @click="emit('open', item.id)"
            >
              {{ item.title }}
            </button>
            <p class="truncate font-mono text-xs text-muted">
              {{ item.tool }} · {{ item.rule_id }}<span v-if="item.path"> · {{ item.path }}<span v-if="item.start_line">:{{ item.start_line }}</span></span>
            </p>
          </div>
          <FindingsSeverityBadge :severity="item.severity" />
          <span class="shrink-0 text-xs text-muted">{{ t('ai.similar.score', { score: Math.round(item.score * 100) }) }}</span>
        </li>
      </ul>
      <UButton
        v-if="canTriage && selected.length"
        size="sm"
        variant="outline"
        icon="i-lucide-list-checks"
        :label="t('ai.similar.triage', { count: selected.length })"
        data-testid="ai-similar-triage"
        @click="open = true"
      />
      <p class="text-xs text-muted">
        {{ t('ai.similar.help') }}
      </p>
    </template>

    <ConfirmModal
      v-model:open="open"
      :title="t('ai.similar.triageTitle', { count: selected.length })"
      :body="t('ai.similar.triageBody')"
      :confirm-label="t('ai.similar.apply')"
      :loading="applying"
      @confirm="apply"
    >
      <div class="space-y-3">
        <UFormField :label="t('ai.similar.status')">
          <USelect
            v-model="form.status"
            :items="statusItems"
            class="w-full"
          />
        </UFormField>
        <UFormField
          :label="t('ai.similar.reason')"
          :required="needsReason"
        >
          <UTextarea
            v-model="form.reason"
            :rows="2"
            class="w-full"
          />
        </UFormField>
        <UFormField
          v-if="form.status === 'accepted'"
          :label="t('ai.similar.until')"
          required
        >
          <UInput
            v-model="form.until"
            type="date"
          />
        </UFormField>
      </div>
    </ConfirmModal>
  </section>
</template>
