<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Page « Release » d'une analyse de release (CLAUDE.md § 7) : verdict, statut
scanoria/release-gate publié dans la forge, état de la signature du rapport,
téléchargements (rapport JSON signé, SARIF fusionné, SBOM CycloneDX, client
scanoria-verify et clé publique de l'appliance), comparaison F2 avec la
release précédente ou une release choisie, et notes de sécurité (I6) proposées
par IA, annexe non signée. Lecture seule ; indicateurs d'attente pendant le
chargement et tant que l'analyse ou la signature est en cours.
-->

<script setup lang="ts">
interface Counts { critical: number, high: number, medium: number, low: number, info: number }
interface Item { id: string, tool: string, rule_id: string, severity: keyof Counts, title: string, path: string | null }
interface Bucket { total: number, by_severity: Counts, by_tool: Record<string, Counts>, items: Item[] }
interface Comparison { from_scan_id: string, to_scan_id: string, introduced: Bucket, fixed: Bucket, unchanged: Bucket }
interface Publication { outcome: string, details: Record<string, unknown>, at: string }
interface ReleaseView {
  scan_id: string
  project_id: string
  project_name?: string
  tag: string
  commit_sha: string
  source: string | null
  scan_number: number
  scan_status: string
  verdict: string | null
  signed_verdict?: string | null
  report_status: 'pending' | 'signed' | 'error' | null
  report_sha256?: string
  key_fingerprint?: string | null
  signed_at?: string | null
  error?: string | null
  previous_scan_id?: string | null
  comparison: Comparison | null
  gate_context: string
  gate: { state: string, description: string }
  publications: Record<string, Publication>
  files: Record<string, boolean>
}
interface ReleaseItem { scan_id: string, tag: string, report_status: string | null }

const route = useRoute()
const scanId = computed(() => String(route.params.scanId ?? ''))
const { t, te } = useI18n()
const { api } = useApi()
const { label } = useScanText()

const rel = ref<ReleaseView | null>(null)
const loadError = ref('')
const others = ref<ReleaseItem[]>([])
const compareWith = ref<string | undefined>(undefined)
const custom = ref<Comparison | null>(null)
const comparing = ref(false)

function errorText(err: unknown): string {
  const code = (err as { data?: { data?: { code?: string } } })?.data?.data?.code ?? ''
  return te(`releases.errors.${code}`) ? t(`releases.errors.${code}`) : t('releases.errors.load')
}

async function load() {
  try {
    rel.value = await api<ReleaseView>(`/api/releases/${encodeURIComponent(scanId.value)}`)
    loadError.value = ''
    if (!others.value.length) {
      others.value = (await api<{ items: ReleaseItem[] }>('/api/releases', { query: { project: rel.value.project_id } })).items
        .filter(r => r.scan_id !== scanId.value && r.report_status === 'signed')
    }
  }
  catch (err) {
    loadError.value = errorText(err)
  }
}

const waiting = computed(() => !!rel.value && (ACTIVE_STATUSES.includes(rel.value.scan_status) || rel.value.report_status === null || rel.value.report_status === 'pending'))
let timer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  void load()
  timer = setInterval(() => {
    if (waiting.value) void load()
  }, 4000)
})
onBeforeUnmount(() => clearInterval(timer))

watch(compareWith, async (other) => {
  custom.value = null
  if (!other) return
  comparing.value = true
  try {
    custom.value = await api<Comparison>(`/api/releases/${encodeURIComponent(scanId.value)}/compare`, { query: { with: other } })
  }
  catch (err) {
    loadError.value = errorText(err)
  }
  finally {
    comparing.value = false
  }
})

const comparison = computed(() => custom.value ?? rel.value?.comparison ?? null)
const compareOptions = computed(() => others.value.map(r => ({ label: r.tag, value: r.scan_id })))
const title = computed(() => (rel.value ? t('releases.title', { tag: rel.value.tag }) : t('releases.nav')))
useHead({ title })

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const gateColor = (s: string) => (s === 'success' ? 'success' : s === 'pending' ? 'neutral' : 'error')
const signColor = (s: string | null) => (s === 'signed' ? 'success' : s === 'error' ? 'error' : 'neutral')
const verdictText = (v: string | null | undefined) => (v ? label('verdicts', v) : t('releases.noVerdict'))
const files = [
  { name: 'report.json', icon: 'i-lucide-file-badge', key: 'report' },
  { name: 'results.sarif', icon: 'i-lucide-file-json', key: 'sarif' },
  { name: 'sbom.cdx.json', icon: 'i-lucide-package', key: 'sbom' },
  { name: 'vex.json', icon: 'i-lucide-shield-question', key: 'vex' },
] as const
const pubKeys = [['gate', 'gate.published'], ['assets', 'assets'], ['notes', 'notes.uploaded']] as const
const pubText = (p: Publication) => {
  const outcome = String(p.details?.outcome ?? p.details?.state ?? p.outcome)
  return te(`releases.publication.outcomes.${outcome}`) ? t(`releases.publication.outcomes.${outcome}`) : outcome
}
const findingLink = (f: Item) => `/findings?${new URLSearchParams({ project_id: rel.value?.project_id ?? '', tool: f.tool, q: f.rule_id, status: 'all' }).toString()}`
</script>

<template>
  <PageShell :title="title">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
      data-testid="release-error"
    />
    <div
      v-if="!rel && !loadError"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="rel">
      <UCard data-testid="release-summary">
        <div class="flex flex-wrap items-center gap-2">
          <UBadge
            :color="verdictColor(rel.verdict)"
            variant="solid"
            :label="verdictText(rel.verdict)"
            data-testid="release-verdict"
          />
          <UBadge
            :color="gateColor(rel.gate.state)"
            variant="subtle"
            :label="t(`releases.gate.${rel.gate.state}`)"
            data-testid="release-gate"
          />
          <UBadge
            :color="signColor(rel.report_status)"
            variant="subtle"
            :label="t(`releases.signature.${rel.report_status ?? 'none'}`)"
            data-testid="release-signature"
          />
          <UIcon
            v-if="waiting"
            name="i-lucide-loader-circle"
            class="animate-spin text-muted"
            data-testid="release-waiting"
          />
        </div>
        <UAlert
          v-if="rel.signed_verdict && rel.verdict && rel.signed_verdict !== rel.verdict"
          class="mt-3"
          color="warning"
          variant="subtle"
          :title="t('releases.verdictChanged', { signed: verdictText(rel.signed_verdict), current: verdictText(rel.verdict) })"
          data-testid="release-verdict-changed"
        />
        <UAlert
          v-if="rel.report_status === 'error'"
          class="mt-3"
          color="error"
          variant="subtle"
          :title="t('releases.reportError')"
          :description="rel.error ?? undefined"
        />
        <dl class="mt-4 grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt class="text-muted">
              {{ t('releases.tag') }}
            </dt>
            <dd class="font-mono text-xs">
              {{ rel.tag }}
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('releases.commit') }}
            </dt>
            <dd class="font-mono text-xs break-all">
              {{ rel.commit_sha }}
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('releases.source') }}
            </dt>
            <dd>{{ te(`releases.sources.${rel.source}`) ? t(`releases.sources.${rel.source}`) : '—' }}</dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('releases.scan') }}
            </dt>
            <dd>
              <NuxtLink
                :to="`/scans/${rel.scan_id}`"
                class="text-primary"
              >
                {{ rel.project_name ?? '' }} #{{ rel.scan_number }}
              </NuxtLink>
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('releases.status') }} ({{ rel.gate_context }})
            </dt>
            <dd>{{ rel.gate.description }}</dd>
          </div>
          <div v-if="rel.key_fingerprint">
            <dt class="text-muted">
              {{ t('releases.key') }}
            </dt>
            <dd class="font-mono text-xs break-all">
              {{ rel.key_fingerprint }}
            </dd>
          </div>
        </dl>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('releases.files.title') }}
          </h2>
        </template>
        <div class="flex flex-wrap gap-2">
          <UButton
            v-for="f in files"
            :key="f.name"
            :to="`/api/releases/${rel.scan_id}/${f.name}`"
            external
            download
            :disabled="!rel.files[f.name]"
            :icon="f.icon"
            color="neutral"
            variant="soft"
            :label="t(`releases.files.${f.key}`)"
            :data-testid="`release-file-${f.key}`"
          />
          <UButton
            to="/api/releases/client"
            external
            download
            icon="i-lucide-shield-check"
            color="neutral"
            variant="ghost"
            :label="t('releases.files.verify')"
          />
          <UButton
            to="/api/system/appliance-key"
            external
            icon="i-lucide-key-round"
            color="neutral"
            variant="ghost"
            :label="t('releases.files.key')"
          />
        </div>
        <p class="mt-3 text-xs text-muted">
          {{ t('releases.files.help') }}
        </p>
        <ul
          class="mt-3 space-y-1 text-sm"
          data-testid="release-publications"
        >
          <li
            v-for="[k, action] in pubKeys"
            :key="k"
          >
            <span class="text-muted">{{ t(`releases.publication.${k}`) }} :</span>
            {{ rel.publications[action] ? pubText(rel.publications[action]) : t('releases.publication.none') }}
          </li>
        </ul>
      </UCard>

      <UCard data-testid="release-compare">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h2 class="font-semibold">
              {{ t('releases.compare.title') }}
            </h2>
            <div class="flex items-center gap-2">
              <UIcon
                v-if="comparing"
                name="i-lucide-loader-circle"
                class="animate-spin text-muted"
              />
              <USelect
                v-if="compareOptions.length"
                v-model="compareWith"
                :items="compareOptions"
                :placeholder="t('releases.compare.choose')"
                class="w-48"
              />
            </div>
          </div>
        </template>
        <p
          v-if="!comparison"
          class="text-sm text-muted"
        >
          {{ t('releases.compare.none') }}
        </p>
        <template v-else>
          <div class="grid gap-3 sm:grid-cols-3">
            <div
              v-for="b in (['introduced', 'fixed', 'unchanged'] as const)"
              :key="b"
              class="rounded border border-default p-3"
            >
              <p class="text-sm text-muted">
                {{ t(`releases.compare.${b}`) }}
              </p>
              <p class="text-2xl font-semibold">
                {{ comparison[b].total }}
              </p>
              <p class="text-xs text-muted">
                <template
                  v-for="s in SEVERITIES"
                  :key="s"
                >
                  <span v-if="comparison[b].by_severity[s]">{{ t(`findings.severity.${s}`) }} {{ comparison[b].by_severity[s] }} · </span>
                </template>
              </p>
            </div>
          </div>
          <div
            v-for="b in (['introduced', 'fixed'] as const)"
            :key="`items-${b}`"
            class="mt-4"
          >
            <h3
              v-if="comparison[b].items.length"
              class="mb-1 text-sm font-medium"
            >
              {{ t(`releases.compare.${b}`) }}
            </h3>
            <ul class="space-y-1 text-sm">
              <li
                v-for="f in comparison[b].items"
                :key="f.id"
                class="flex flex-wrap items-center gap-2"
              >
                <UBadge
                  :color="f.severity === 'critical' || f.severity === 'high' ? 'error' : 'neutral'"
                  variant="subtle"
                  size="sm"
                  :label="t(`findings.severity.${f.severity}`)"
                />
                <NuxtLink
                  :to="findingLink(f)"
                  class="text-primary"
                >
                  {{ f.title }}
                </NuxtLink>
                <span class="text-xs text-muted">{{ f.tool }} · {{ f.path ?? '—' }}</span>
              </li>
            </ul>
          </div>
        </template>
      </UCard>

      <AiTaskPanel
        v-if="rel.report_status === 'signed'"
        kind="release-notes"
        :subject-id="rel.scan_id"
        :title="t('releases.notes.title')"
        icon="i-lucide-scroll-text"
        :askable="false"
      >
        <template #default="{ output }">
          <div
            class="space-y-2 text-sm"
            data-testid="release-notes"
          >
            <p class="font-medium">
              {{ output.headline }}
            </p>
            <div
              v-for="k in (['fixed', 'introduced', 'accepted'] as const)"
              :key="k"
            >
              <p class="text-xs text-muted">
                {{ t(`releases.notes.${k}`) }}
              </p>
              <p class="whitespace-pre-line">
                {{ output[k] }}
              </p>
            </div>
            <p class="text-xs text-muted">
              {{ t('releases.notes.unsigned') }}
            </p>
          </div>
        </template>
      </AiTaskPanel>
    </template>
  </PageShell>
</template>
