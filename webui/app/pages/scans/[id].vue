<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'une analyse : état, plan figé (G11) avec la raison de chaque module
(décidé automatiquement), modules (état, durée, journal téléchargeable, G20),
couverture (G15) et verdict ; résumé (I5) et diagnostic d'un échec (I15)
proposés par IA quand le connecteur est actif. Annuler, relancer et rejouer à l'identique
passent par une modale de la console, avec indicateur d'attente.
-->

<script setup lang="ts">
const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const { t } = useI18n()
const session = useSession()
const canAct = computed(() => session.can('operator'))
const fmt = useFormat()
const { api } = useApi()
const { label, scanError } = useScanText()
const toast = useToast()

const scan = ref<ScanDetail | null>(null)
const loadError = ref('')
async function load() {
  try {
    scan.value = await api<ScanDetail>(`/api/scans/${encodeURIComponent(id.value)}`)
    loadError.value = ''
  }
  catch (err) {
    loadError.value = scanError(err)
  }
}
const active = computed(() => !!scan.value && ACTIVE_STATUSES.includes(scan.value.status))
const FAILED_MODULE = ['error', 'timeout', 'oom', 'invalid-output', 'missing']
const failed = computed(() => !!scan.value && !active.value && scan.value.status !== 'cancelled'
  && (scan.value.status === 'error' || scan.value.modules.some(m => FAILED_MODULE.includes(m.status))))
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void load()
  timer = setInterval(() => {
    if (active.value) void load()
  }, 3000)
})
onBeforeUnmount(() => clearInterval(timer))

const title = computed(() => (scan.value ? `${scan.value.project_name} #${scan.value.number}` : t('scans.title')))
useHead({ title })

// --- Actions ---
type Action = 'cancel' | 'retry' | 'replay'
const pending = ref<Action | null>(null)
const modalOpen = ref(false)
const busy = ref(false)
function ask(action: Action) {
  pending.value = action
  modalOpen.value = true
}
async function confirmAction() {
  if (!pending.value || !scan.value) return
  busy.value = true
  try {
    const res = await api<{ scan_id: string, merged?: boolean }>(`/api/scans/${scan.value.id}/${pending.value}`, { method: 'POST' })
    modalOpen.value = false
    if (pending.value === 'cancel') {
      toast.add({ title: t('scans.actions.cancelled'), color: 'success' })
      await load()
    }
    else {
      toast.add({ title: res.merged ? t('scans.actions.merged') : t('scans.actions.queued'), color: 'success' })
      await navigateTo(`/scans/${res.scan_id}`)
    }
  }
  catch (err) {
    toast.add({ title: scanError(err), color: 'error' })
  }
  finally {
    busy.value = false
  }
}
const modalTitle = computed(() => (pending.value ? t(`scans.actions.${pending.value}Title`) : ''))
const modalBody = computed(() => (pending.value ? t(`scans.actions.${pending.value}Body`) : ''))

// --- Affichage ---
const planModules = computed(() => scan.value?.plan?.modules ?? [])
const gaps = computed(() => scan.value?.coverage?.gaps ?? scan.value?.plan?.gaps ?? [])
const source = computed(() => scan.value?.coverage?.source ?? null)
// 0.6 (chantier C) : exclusions communes (G15), travail en mémoire (V9), miroir Git (V2).
const excluded = computed(() => scan.value?.coverage?.excluded ?? [])
const execNotes = computed(() => {
  const s = source.value
  const notes: string[] = []
  if (s?.mirror && ['hit', 'fetched', 'created', 'ephemeral'].includes(s.mirror)) notes.push(t(`scans.coverage.mirror.${s.mirror}`))
  if (s?.workdir === 'tmpfs' || s?.workdir === 'disk') notes.push(t(`scans.coverage.workdir.${s.workdir}`))
  return notes
})
const verdictJson = computed(() => JSON.stringify(scan.value?.verdict_details ?? {}, null, 2))
const duration = (ms: number | null) => (ms === null ? '—' : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`)
const moduleRow = (moduleId: string) => scan.value?.modules.find(m => m.module_id === moduleId)
function gapText(g: CoverageGap): string {
  if (g.kind === 'profile-category' || (!g.kind && g.category)) {
    return t('scans.gaps.category', { category: label('category', g.category), reason: label('gapReason', g.reason) })
  }
  // 0.6 (V6, V3) : module sans fichier concerné ; module qui a lu le dépôt faute de SBOM.
  if (g.kind === 'not-applicable' || g.kind === 'sbom-fallback') {
    return t(g.kind === 'not-applicable' ? 'scans.gaps.notApplicable' : 'scans.gaps.sbomFallback', { module: g.module ?? '?' })
  }
  // 0.7 (§ 3.5) : module d'analyse par IA en échec, hors verdict mais signalé.
  if (g.kind === 'ai-module-failed') return t('scans.gaps.aiModuleFailed', { module: g.module ?? '?', code: g.code ?? '?' })
  if (g.kind === 'profile-module' || (!g.kind && g.module)) {
    return t('scans.gaps.module', { module: g.module ?? '?', reason: label('gapReason', g.reason) })
  }
  const what = [g.path, g.detail].filter(Boolean).join(' · ')
  return what ? `${label('gapKind', g.kind)} : ${what}` : label('gapKind', g.kind)
}
const reasonText = (m: PlanModule) => (m.reason === 'included'
  ? t('scans.plan.included')
  : t('scans.plan.byCategory', { categories: m.categories.filter(c => scan.value?.plan?.profile.categories.includes(c)).map(c => label('category', c)).join(', ') }))
</script>

<template>
  <PageShell :title="title">
    <template #actions>
      <template v-if="scan && canAct">
        <UButton
          v-if="active && scan.status !== 'ingesting'"
          icon="i-lucide-circle-stop"
          color="error"
          variant="soft"
          :label="t('scans.actions.cancel')"
          @click="ask('cancel')"
        />
        <UButton
          v-if="!active"
          icon="i-lucide-rotate-cw"
          color="neutral"
          variant="soft"
          :label="t('scans.actions.retry')"
          @click="ask('retry')"
        />
        <UButton
          v-if="!active && scan.plan"
          icon="i-lucide-repeat"
          color="primary"
          variant="soft"
          :label="t('scans.actions.replay')"
          @click="ask('replay')"
        />
      </template>
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!scan"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-else>
      <UCard>
        <div class="flex flex-wrap items-center gap-2">
          <UBadge
            :color="scanStatusColor(scan.status)"
            variant="subtle"
            :label="label('statuses', scan.status)"
          />
          <UIcon
            v-if="active"
            name="i-lucide-loader-circle"
            class="animate-spin text-muted"
          />
          <UBadge
            v-if="scan.verdict"
            :color="verdictColor(scan.verdict)"
            variant="solid"
            :label="label('verdicts', scan.verdict)"
          />
          <span
            v-if="scan.queue_position"
            class="text-sm text-muted"
          >{{ t('scans.position', { position: scan.queue_position }) }}</span>
        </div>
        <dl class="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt class="text-muted">
              {{ t('scans.project') }}
            </dt>
            <dd>{{ scan.project_name }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.ref') }}
            </dt>
            <dd class="font-mono text-xs">
              {{ scan.ref }}<template v-if="scan.commit_sha">
                @ {{ scan.commit_sha }}
              </template>
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.trigger') }}
            </dt>
            <dd>
              {{ label('triggers', scan.trigger) }}
              <FindingsExternalBadge
                v-if="scan.external_source"
                origin="external"
                :source="scan.external_source"
              />
              <NuxtLink
                v-if="scan.replay_of"
                :to="`/scans/${scan.replay_of}`"
                class="text-primary"
              >({{ t('scans.replayOf') }})</NuxtLink>
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.profile') }} · {{ t('scans.gate') }}
            </dt>
            <dd>{{ scan.profile }} · {{ scan.gate }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.priority') }}
            </dt>
            <dd>
              {{ scan.priority }}<template v-if="scan.status === 'queued' && scan.effective_priority !== scan.priority">
                → {{ scan.effective_priority }} ({{ t('scans.aging') }})
              </template>
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.attempt') }}
            </dt>
            <dd>{{ scan.attempt }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.queuedAt') }}
            </dt>
            <dd>{{ fmt.date(scan.queued_at) }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.startedAt') }}
            </dt>
            <dd>{{ fmt.date(scan.started_at) }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.finishedAt') }}
            </dt>
            <dd>{{ fmt.date(scan.finished_at) }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('scans.requestedBy') }}
            </dt>
            <dd>{{ scan.requested_by_username ?? (scan.by_api_token ? t('scans.apiToken') : t('scans.automatic')) }}</dd>
          </div>
        </dl>
        <UAlert
          v-if="scan.error"
          class="mt-4"
          :color="scan.status === 'queued' ? 'warning' : 'error'"
          variant="subtle"
          :title="label('errorClass', scan.error.class)"
          :description="`${scan.error.code ?? ''} ${scan.error.message ?? ''}${scan.error.retry_at ? ` — ${t('scans.retryAt', { at: fmt.date(scan.error.retry_at) })}` : ''}`"
        />
      </UCard>

      <!-- IA (I5, I15) : rien sans connecteur ni pour un projet exclu. -->
      <AiScanSummary
        v-if="scan.status === 'done'"
        :scan-id="scan.id"
      />
      <AiDiagnosis
        v-if="failed"
        :scan-id="scan.id"
      />

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('scans.plan.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('scans.plan.help') }}
          </p>
        </template>
        <p
          v-if="!scan.plan"
          class="text-sm text-muted"
        >
          {{ t('scans.plan.none') }}
        </p>
        <ul
          v-else
          class="divide-y divide-default text-sm"
        >
          <li
            v-for="m in planModules"
            :key="m.id"
            class="flex flex-wrap items-center gap-x-4 gap-y-1 py-2"
          >
            <span class="font-medium">{{ m.id }}</span>
            <span class="font-mono text-xs text-muted">{{ m.version }}<template v-if="m.image_digest"> · {{ m.image_digest.slice(0, 19) }}…</template></span>
            <span class="text-muted">{{ reasonText(m) }}</span>
            <span class="ml-auto flex items-center gap-3">
              <template v-if="moduleRow(m.id)">
                <UBadge
                  :color="scanStatusColor(moduleRow(m.id)!.status)"
                  variant="subtle"
                  :label="label('moduleStatus', moduleRow(m.id)!.status)"
                />
                <span
                  v-if="moduleRow(m.id)!.reused"
                  class="text-muted"
                >
                  <ULink
                    v-if="moduleRow(m.id)!.reused_from_scan"
                    :to="`/scans/${moduleRow(m.id)!.reused_from_scan}`"
                  >{{ t('scans.reusedFrom', { number: moduleRow(m.id)!.reused_from_number }) }}</ULink>
                  <template v-else>{{ t('scans.reused') }}</template>
                </span>
                <span
                  v-else
                  class="text-muted"
                >{{ duration(moduleRow(m.id)!.duration_ms) }}</span>
                <span
                  v-if="moduleRow(m.id)!.results_count !== null"
                  class="text-muted"
                >{{ t('scans.results', { count: moduleRow(m.id)!.results_count }) }}</span>
                <UButton
                  v-if="moduleRow(m.id)!.has_log && canAct"
                  :to="`/api/scans/${scan.id}/modules/${m.id}/log`"
                  external
                  download
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-download"
                  :label="t('scans.log')"
                />
              </template>
            </span>
          </li>
          <li
            v-if="!planModules.length"
            class="py-2 text-muted"
          >
            {{ t('scans.plan.empty') }}
          </li>
        </ul>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('scans.coverage.title') }}
          </h2>
        </template>
        <p
          v-if="source"
          class="mb-2 text-sm text-muted"
        >
          {{ t('scans.coverage.source', { files: source.files, skipped: source.skipped.length }) }}
        </p>
        <p
          v-if="execNotes.length"
          class="mb-2 text-sm text-muted"
          data-testid="exec-notes"
        >
          {{ execNotes.join(' ') }}
        </p>
        <div
          v-if="excluded.length"
          class="mb-2 text-sm"
          data-testid="exec-excluded"
        >
          <p class="font-medium">
            {{ t('scans.coverage.excludedTitle') }}
          </p>
          <ul class="list-disc pl-5 text-muted">
            <li
              v-for="e in excluded"
              :key="e.pattern"
            >
              {{ t('scans.coverage.excluded', { pattern: e.pattern, count: e.count }) }}
            </li>
          </ul>
        </div>
        <ul
          v-if="gaps.length"
          class="list-disc space-y-1 pl-5 text-sm"
        >
          <li
            v-for="(g, i) in gaps"
            :key="i"
          >
            {{ gapText(g) }}
          </li>
        </ul>
        <p
          v-else
          class="text-sm text-muted"
        >
          {{ t('scans.coverage.none') }}
        </p>
      </UCard>

      <SbomComponents
        v-if="!active"
        :scan-id="scan.id"
      />

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('scans.verdict') }}
          </h2>
        </template>
        <p
          v-if="!scan.verdict_details"
          class="text-sm text-muted"
        >
          {{ active ? t('scans.verdictPending') : t('scans.verdictNone') }}
        </p>
        <pre
          v-else
          class="max-h-96 overflow-auto rounded bg-elevated p-3 text-xs"
        >{{ verdictJson }}</pre>
        <!-- Verdict expliqué (I9) : rien sans connecteur IA. -->
        <AiExplanation
          v-if="scan.verdict"
          class="mt-3"
          kind="explain-verdict"
          :subject-id="scan.id"
        />
      </UCard>
    </template>

    <ConfirmModal
      v-model:open="modalOpen"
      :title="modalTitle"
      :body="modalBody"
      :color="pending === 'cancel' ? 'error' : 'primary'"
      :loading="busy"
      @confirm="confirmAction"
    />
  </PageShell>
</template>
