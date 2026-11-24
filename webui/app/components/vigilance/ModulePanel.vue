<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Vigilance d'un module installé, sur sa fiche du catalogue :
- canaris nocturnes (G14) : un échec est signalé, le module n'est jamais désactivé ;
- mise à jour à l'essai (F13) : la version candidate rejoue les dernières
  analyses sans effet de bord, puis adoption (mise à jour normale) ou abandon ;
- projets qui figent une version (G6) et vulnérabilités de l'image (F19).
-->

<script setup lang="ts">
import { reasonOf, type CanaryView, type SelfVuln, type TrialView } from '~/utils/vigilance'

const props = defineProps<{ moduleId: string, isAdmin: boolean, scanner: boolean, busy?: boolean }>()
const emit = defineEmits<{ changed: [] }>()

interface ModuleVigilance {
  canaries: CanaryView[]
  trials: TrialView[]
  trial_candidates: string[]
  pins: { project_id: string, slug: string, name: string, version: string, reason: string }[]
  vulns: SelfVuln[]
}

const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const fmt = useFormat()
const toast = useToast()
const data = ref<ModuleVigilance | null>(null)
const canaryReq = useHelperRequest()
const trialReq = useHelperRequest()
const adoptReq = useHelperRequest()
const abandonReq = useHelperRequest()

async function load() {
  try {
    data.value = await api<ModuleVigilance>(`/api/catalog/modules/${encodeURIComponent(props.moduleId)}/vigilance`)
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
}
onMounted(load)

// Un essai en cours se suit sans recharger la page.
let timer: ReturnType<typeof setInterval> | undefined
const running = computed(() => (data.value?.trials ?? []).some(x => x.status === 'running'))
watch(running, (on) => {
  if (timer) clearInterval(timer)
  timer = on ? setInterval(load, 10_000) : undefined
})
onBeforeUnmount(() => timer && clearInterval(timer))

const lastCanary = computed(() => data.value?.canaries[0] ?? null)
const canaryMissing = (c: CanaryView) => c.details.expect.filter(e => !e.ok)

async function runCanary() {
  await canaryReq.run('/api/vigilance/canaries', { ids: [props.moduleId] }, { pollMs: 3000 })
  await load()
  emit('changed')
}

// F13 : démarrer
const startOpen = ref(false)
const candidate = ref<string | undefined>(undefined)
const sample = ref(3)
watch(() => data.value?.trial_candidates, (c) => {
  if (c?.length && (!candidate.value || !c.includes(candidate.value))) candidate.value = c[c.length - 1]
}, { immediate: true })
const sortedCandidates = computed(() => [...(data.value?.trial_candidates ?? [])])

function reasonMessage(err: unknown): string {
  const r = reasonOf(err)
  return r && te(`vigilance.reasons.${r}`) ? t(`vigilance.reasons.${r}`) : errorMessage(err)
}

async function startTrial() {
  if (!candidate.value) return
  startOpen.value = false
  try {
    await trialReq.run(`/api/catalog/modules/${encodeURIComponent(props.moduleId)}/trials`,
      { version: candidate.value, sample_size: sample.value }, { pollMs: 3000 })
  }
  catch (err) {
    toast.add({ title: reasonMessage(err), color: 'error' })
  }
  await load()
}

// F13 : adopter, abandonner
const adoptTarget = ref<TrialView | null>(null)
const abandonTarget = ref<TrialView | null>(null)
const adoptOpen = computed({
  get: () => !!adoptTarget.value,
  set: (v: boolean) => {
    if (!v) adoptTarget.value = null
  },
})
const abandonOpen = computed({
  get: () => !!abandonTarget.value,
  set: (v: boolean) => {
    if (!v) abandonTarget.value = null
  },
})

async function adopt() {
  const tr = adoptTarget.value
  if (!tr) return
  adoptTarget.value = null
  try {
    await adoptReq.run(`/api/catalog/modules/${encodeURIComponent(props.moduleId)}/trials/${tr.id}/adopt`, {})
  }
  catch (err) {
    toast.add({ title: reasonMessage(err), color: 'error' })
  }
  await load()
  emit('changed')
}
async function abandon() {
  const tr = abandonTarget.value
  if (!tr) return
  abandonTarget.value = null
  try {
    await abandonReq.run(`/api/catalog/modules/${encodeURIComponent(props.moduleId)}/trials/${tr.id}/abandon`, {}, { pollMs: 3000 })
  }
  catch (err) {
    toast.add({ title: reasonMessage(err), color: 'error' })
  }
  await load()
}

const anyRunning = computed(() => props.busy || canaryReq.running.value || trialReq.running.value || adoptReq.running.value || abandonReq.running.value)
const statusColor = (s: TrialView['status']) => (s === 'done' || s === 'adopted' ? 'success' : s === 'error' ? 'error' : s === 'running' ? 'info' : 'neutral')
const seconds = (ms: number | null | undefined) => (ms === null || ms === undefined ? '—' : (ms / 1000).toFixed(1))
</script>

<template>
  <UCard
    v-if="data"
    data-testid="module-vigilance"
  >
    <template #header>
      <h2 class="font-semibold">
        {{ t('vigilance.module.title') }}
      </h2>
      <p class="text-sm text-muted">
        {{ t('vigilance.module.help') }}
      </p>
    </template>

    <div class="space-y-5">
      <section v-if="scanner">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold">
            {{ t('vigilance.panel.canaries') }}
          </h3>
          <UButton
            v-if="isAdmin"
            icon="i-lucide-bird"
            size="sm"
            color="neutral"
            variant="subtle"
            :loading="canaryReq.running.value"
            :disabled="anyRunning"
            :label="t('vigilance.module.runCanary')"
            @click="runCanary"
          />
        </div>
        <RequestProgress
          :active="canaryReq.running.value"
          :label="canaryReq.label.value"
        />
        <p
          v-if="!lastCanary"
          class="text-sm text-muted"
        >
          {{ t('vigilance.panel.noCanary') }}
        </p>
        <template v-else>
          <p class="text-sm">
            <UBadge
              :color="lastCanary.ok ? 'success' : 'error'"
              variant="subtle"
              :label="lastCanary.ok ? t('vigilance.canary.ok') : t('vigilance.canary.failed')"
            />
            {{ t('vigilance.canary.last', { version: lastCanary.module_version, date: fmt.date(lastCanary.run_at) }) }}
          </p>
          <p
            v-if="!lastCanary.ok"
            class="text-sm text-error"
          >
            {{ t('vigilance.canary.notDisabled') }}
          </p>
          <ul
            v-if="!lastCanary.ok"
            class="text-sm"
          >
            <li v-if="lastCanary.details.error">
              {{ te(`codes.${lastCanary.details.error.code}`) ? t(`codes.${lastCanary.details.error.code}`) : lastCanary.details.error.code }}
            </li>
            <li
              v-for="(e, i) in canaryMissing(lastCanary)"
              :key="i"
            >
              {{ t('vigilance.canary.missing', { rule: e.rule ?? e.category ?? '?', min: e.min, found: e.found }) }}
            </li>
          </ul>
          <p class="mt-1 flex flex-wrap gap-1">
            <UBadge
              v-for="c in data.canaries"
              :key="c.run_at"
              :color="c.ok ? 'success' : 'error'"
              variant="outline"
              size="sm"
              :label="fmt.date(c.run_at)"
            />
          </p>
        </template>
      </section>

      <section v-if="scanner">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <h3 class="text-sm font-semibold">
            {{ t('vigilance.trial.title') }}
          </h3>
          <UButton
            v-if="isAdmin && sortedCandidates.length"
            icon="i-lucide-flask-conical"
            size="sm"
            color="neutral"
            variant="subtle"
            :disabled="anyRunning || running"
            :label="t('vigilance.trial.start')"
            @click="startOpen = true"
          />
        </div>
        <p class="text-sm text-muted">
          {{ sortedCandidates.length ? t('vigilance.trial.help') : t('vigilance.trial.noCandidate') }}
        </p>
        <RequestProgress
          :active="trialReq.running.value"
          :label="trialReq.label.value"
        />
        <RequestProgress
          :active="adoptReq.running.value"
          :label="adoptReq.label.value"
        />
        <RequestProgress
          :active="abandonReq.running.value"
          :label="abandonReq.label.value"
        />
        <ul class="mt-2 space-y-3">
          <li
            v-for="tr in data.trials"
            :key="tr.id"
            class="rounded border border-default p-3 text-sm"
          >
            <div class="flex flex-wrap items-center gap-2">
              <UBadge
                :color="statusColor(tr.status)"
                variant="subtle"
                :label="t(`vigilance.trial.status.${tr.status}`)"
              />
              <span>{{ t('vigilance.trial.versions', { from: tr.from_version, to: tr.to_version }) }}</span>
              <span class="text-muted">{{ fmt.date(tr.started_at) }}</span>
              <UIcon
                v-if="tr.status === 'running'"
                name="i-lucide-loader-circle"
                class="size-4 animate-spin"
              />
            </div>
            <p v-if="tr.status === 'running'">
              {{ t('vigilance.trial.progress', { finished: tr.progress.finished, total: tr.progress.total, sample: tr.sample_size }) }}
            </p>
            <template v-if="tr.summary">
              <p v-if="tr.summary.note === 'no-sample'">
                {{ t('vigilance.trial.noSample') }}
              </p>
              <p v-else-if="tr.summary.error">
                {{ te(`codes.${tr.summary.error}`) ? t(`codes.${tr.summary.error}`) : tr.summary.error }}
              </p>
              <p v-if="tr.status !== 'running' && !tr.summary.note">
                {{ t('vigilance.trial.diff', { new: tr.summary.new, gone: tr.summary.gone, unchanged: tr.summary.unchanged, scans: tr.summary.scans, failed: tr.summary.failed }) }}
                · {{ t('vigilance.trial.duration', { old: seconds(tr.summary.duration_old_ms), new: seconds(tr.summary.duration_new_ms) }) }}
              </p>
              <details
                v-if="tr.summary.per_scan?.some(p => p.new_examples.length || p.gone_examples.length)"
                class="mt-1"
              >
                <summary class="cursor-pointer text-muted">
                  {{ t('vigilance.trial.examples') }}
                </summary>
                <ul class="font-mono text-xs">
                  <template
                    v-for="p in tr.summary.per_scan"
                    :key="p.trial_scan_id"
                  >
                    <li
                      v-for="(e, i) in p.new_examples"
                      :key="`n${i}`"
                    >
                      + {{ e.rule }} {{ e.path ?? '' }}
                    </li>
                    <li
                      v-for="(e, i) in p.gone_examples"
                      :key="`g${i}`"
                    >
                      − {{ e.rule }} {{ e.path ?? '' }}
                    </li>
                  </template>
                </ul>
              </details>
            </template>
            <div
              v-if="isAdmin && ['running', 'done', 'error'].includes(tr.status)"
              class="mt-2 flex gap-2"
            >
              <UButton
                v-if="tr.status === 'done'"
                size="sm"
                icon="i-lucide-check"
                :disabled="anyRunning"
                :label="t('vigilance.trial.adopt')"
                @click="adoptTarget = tr"
              />
              <UButton
                size="sm"
                color="neutral"
                variant="ghost"
                icon="i-lucide-x"
                :disabled="anyRunning"
                :label="t('vigilance.trial.abandon')"
                @click="abandonTarget = tr"
              />
            </div>
          </li>
        </ul>
      </section>

      <section v-if="data.pins.length">
        <h3 class="text-sm font-semibold">
          {{ t('vigilance.module.pins') }}
        </h3>
        <ul class="text-sm">
          <li
            v-for="p in data.pins"
            :key="p.project_id"
          >
            <NuxtLink
              :to="`/projects/${p.project_id}`"
              class="underline"
            >
              {{ p.name }}
            </NuxtLink>
            : {{ p.version }} <span class="text-muted">({{ p.reason }})</span>
          </li>
        </ul>
      </section>

      <section v-if="data.vulns.length">
        <h3 class="text-sm font-semibold text-warning">
          {{ t('vigilance.module.vulns', { count: data.vulns.length }) }}
        </h3>
        <ul class="font-mono text-xs">
          <li
            v-for="v in data.vulns.slice(0, 20)"
            :key="`${v.vuln_id}|${v.purl}`"
          >
            {{ v.severity }} · {{ v.vuln_id }} · {{ v.purl }}
            <span v-if="v.fixed_version">→ {{ v.fixed_version }}</span>
          </li>
        </ul>
      </section>
    </div>

    <ConfirmModal
      v-model:open="startOpen"
      :title="t('vigilance.trial.startTitle')"
      :body="t('vigilance.trial.startBody')"
      :confirm-label="t('vigilance.trial.start')"
      @confirm="startTrial"
    >
      <UFormField :label="t('vigilance.trial.candidate')">
        <USelect
          v-model="candidate"
          :items="sortedCandidates"
          class="w-full"
        />
      </UFormField>
      <UFormField :label="t('vigilance.trial.sample')">
        <UInputNumber
          v-model="sample"
          :min="1"
          :max="50"
        />
      </UFormField>
    </ConfirmModal>
    <ConfirmModal
      v-model:open="adoptOpen"
      :title="t('vigilance.trial.adoptTitle', { version: adoptTarget?.to_version ?? '' })"
      :body="t('vigilance.trial.adoptBody')"
      :confirm-label="t('vigilance.trial.adopt')"
      @confirm="adopt"
    />
    <ConfirmModal
      v-model:open="abandonOpen"
      color="warning"
      :title="t('vigilance.trial.abandonTitle', { version: abandonTarget?.to_version ?? '' })"
      :body="t('vigilance.trial.abandonBody')"
      :confirm-label="t('vigilance.trial.abandon')"
      @confirm="abandon"
    />
  </UCard>
</template>
