<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Résultats unifiés (§ 6.3) : liste filtrée et paginée côté serveur, vue par
projet, détail dans un panneau latéral avec le tri (operator), le suivi des
secrets (F7) et la mise en évidence des paquets malveillants (H4). Les
filtres se lisent dans l'adresse (?project_id=…&scan_id=…&secret=true…).
Tout texte venu d'un scanner est affiché comme texte, jamais comme HTML.
-->

<script setup lang="ts">
import type { TableColumn, TableRow } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'
import { CATEGORIES, FINDING_STATUSES, SEVERITIES } from '#shared/analysis'

const { t, te } = useI18n()
useHead({ title: computed(() => t('findings.title')) })

const route = useRoute()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()

interface Pkg { ecosystem: string | null, name: string, version: string | null, fixed: string[] }
interface FindingRow {
  id: string
  project_id: string
  project_slug: string
  project_name: string
  fingerprint: string
  tool: string
  rule_id: string
  category: string
  severity: string
  native_severity: string | null
  title: string
  path: string | null
  start_line: number | null
  vuln_ids: string[]
  package: Pkg | null
  malicious: boolean
  secret_type: string | null
  secret_state: string | null
  status: string
  status_until: string | null
  is_new: boolean
  first_seen_at: string
  updated_at: string
}
interface FindingDetail extends FindingRow {
  message: string | null
  end_line: number | null
  snippet: string | null
  cwe: string[]
  status_reason: string | null
  status_by: string | null
  status_at: string | null
  secret_state_by: string | null
  secret_state_at: string | null
  first_commit: string | null
  last_commit: string | null
  accepted_expired: boolean
  revoke_pending_days: number | null
  scans: { id: string, number: number, ref: string, is_new: boolean, queued_at: string }[]
}
interface SummaryRow {
  project_id: string
  project_slug: string
  project_name: string
  open: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  secrets_to_revoke: number
  malicious: number
}

const PAGE = 50
const page = ref(1)
const q = route.query
const str = (v: unknown) => (typeof v === 'string' ? v : '')
const filters = reactive({
  project_id: str(q.project_id) || 'all',
  scan_id: str(q.scan_id),
  tool: str(q.tool),
  severity: str(q.severity) || 'all',
  category: str(q.category) || 'all',
  status: str(q.status) || 'open',
  q: str(q.q),
  is_new: q.is_new === 'true',
  secret: q.secret === 'true',
  malicious: q.malicious === 'true',
})
const items = ref<FindingRow[]>([])
const total = ref(0)
const loading = ref(false)
const summary = ref<SummaryRow[]>([])

async function loadSummary() {
  try {
    summary.value = (await api<{ projects: SummaryRow[] }>('/api/findings/summary')).projects
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
}

function query(): Record<string, unknown> {
  const out: Record<string, unknown> = { limit: PAGE, offset: (page.value - 1) * PAGE }
  if (filters.project_id !== 'all') out.project_id = filters.project_id
  if (filters.scan_id) out.scan_id = filters.scan_id
  if (/^[a-z0-9][a-z0-9-]{1,40}$/.test(filters.tool.trim())) out.tool = filters.tool.trim()
  if (filters.severity !== 'all') out.severity = filters.severity
  if (filters.category !== 'all') out.category = filters.category
  if (filters.status === 'open') out.status = 'new,confirmed'
  else if (filters.status !== 'all') out.status = filters.status
  if (filters.q.trim()) out.q = filters.q.trim().slice(0, 200)
  if (filters.is_new) out.is_new = 'true'
  if (filters.secret) out.secret = 'true'
  if (filters.malicious) out.malicious = 'true'
  return out
}

// Seule la réponse de la dernière requête est affichée (filtres changés en cours de route).
let loadSeq = 0
async function load() {
  const seq = ++loadSeq
  loading.value = true
  try {
    const res = await api<{ items: FindingRow[], total: number }>('/api/findings', { query: query() })
    if (seq !== loadSeq) return
    items.value = res.items
    total.value = res.total
    void loadSuggestions(res.items)
  }
  catch (err) {
    if (seq === loadSeq) toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    if (seq === loadSeq) loading.value = false
  }
}
// Pré-tri suggéré par IA (I3) à côté du statut « nouveau » : indice seulement,
// le statut ne change que par un clic. Rien sans connecteur.
const suggestions = ref<Record<string, { value: string }>>({})
async function loadSuggestions(rows: FindingRow[]) {
  const ids = rows.filter(r => r.status === 'new').map(r => r.id)
  if (!ids.length) {
    suggestions.value = {}
    return
  }
  try {
    suggestions.value = (await api<{ items: Record<string, { value: string }> }>('/api/ai/suggestions', { query: { kind: 'triage-finding', ids: ids.join(',') } })).items
  }
  catch {
    suggestions.value = {}
  }
}
const SUGGESTION_COLORS: Record<string, 'success' | 'warning' | 'error'> = { 'likely-false-positive': 'success', 'to-confirm': 'warning', 'likely-true-positive': 'error' }

const reloading = ref(false)
async function reloadAll() {
  reloading.value = true
  try {
    await Promise.all([load(), loadSummary()])
  }
  finally {
    reloading.value = false
  }
}
onMounted(reloadAll)
watch(page, load)
let debounce: ReturnType<typeof setTimeout> | undefined
watch(filters, () => {
  clearTimeout(debounce)
  debounce = setTimeout(() => {
    if (page.value !== 1) page.value = 1
    else void load()
  }, 300)
})
onBeforeUnmount(() => clearTimeout(debounce))

function resetFilters() {
  Object.assign(filters, { project_id: 'all', scan_id: '', tool: '', severity: 'all', category: 'all', status: 'open', q: '', is_new: false, secret: false, malicious: false })
}

const totals = computed(() => summary.value.reduce((acc, p) => ({
  malicious: acc.malicious + p.malicious,
  secrets: acc.secrets + p.secrets_to_revoke,
}), { malicious: 0, secrets: 0 }))

const projectItems = computed(() => [
  { label: t('findings.filters.allProjects'), value: 'all' },
  ...summary.value.map(p => ({ label: p.project_name, value: p.project_id })),
])
const severityItems = computed(() => [
  { label: t('findings.filters.all'), value: 'all' },
  ...SEVERITIES.map(s => ({ label: t(`findings.severity.${s}`), value: s })),
])
const categoryItems = computed(() => [
  { label: t('findings.filters.all'), value: 'all' },
  ...CATEGORIES.map(c => ({ label: t(`findings.categories.${c}`), value: c })),
])
const statusItems = computed(() => [
  { label: `${t('findings.status.new')} + ${t('findings.status.confirmed')}`, value: 'open' },
  { label: t('findings.filters.all'), value: 'all' },
  ...FINDING_STATUSES.map(s => ({ label: t(`findings.status.${s}`), value: s })),
])

const categoryLabel = (c: string) => (te(`findings.categories.${c}`) ? t(`findings.categories.${c}`) : c)
const location = (r: { path: string | null, start_line: number | null, package: Pkg | null }) =>
  r.package ? `${r.package.name}@${r.package.version ?? '?'}` : r.path ? `${r.path}${r.start_line ? `:${r.start_line}` : ''}` : '—'
const statusColor = (s: string) => (s === 'new' ? 'warning' : s === 'confirmed' ? 'error' : s === 'fixed' ? 'success' : 'neutral')

const UBadge = resolveComponent('UBadge')
const SeverityBadge = resolveComponent('FindingsSeverityBadge')
const columns = computed<TableColumn<FindingRow>[]>(() => [
  { accessorKey: 'severity', header: t('findings.columns.severity'), cell: ({ row }) => h(SeverityBadge, { severity: row.original.severity }) },
  {
    id: 'title',
    header: t('findings.columns.title'),
    cell: ({ row }) => h('div', { class: 'flex flex-wrap items-center gap-1' }, [
      row.original.malicious ? h(UBadge, { color: 'error', variant: 'solid', icon: 'i-lucide-skull', label: t('findings.badges.malicious') }) : null,
      row.original.secret_type ? h(UBadge, { color: 'warning', variant: 'outline', icon: 'i-lucide-key-round', label: t('findings.badges.secret') }) : null,
      row.original.is_new ? h(UBadge, { color: 'info', variant: 'subtle', label: t('findings.badges.new') }) : null,
      h('span', { class: 'font-medium' }, row.original.title),
    ]),
  },
  { accessorKey: 'project_name', header: t('findings.columns.project') },
  { accessorKey: 'tool', header: t('findings.columns.tool'), cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.tool) },
  { id: 'location', header: t('findings.columns.location'), cell: ({ row }) => h('span', { class: 'font-mono text-xs break-all' }, location(row.original)) },
  {
    accessorKey: 'status',
    header: t('findings.columns.status'),
    cell: ({ row }) => {
      const status = h(UBadge, { color: statusColor(row.original.status), variant: 'subtle', label: t(`findings.status.${row.original.status}`) })
      const s = row.original.status === 'new' ? suggestions.value[row.original.id] : undefined
      if (!s || !SUGGESTION_COLORS[s.value]) return status
      return h('div', { class: 'flex flex-wrap items-center gap-1' }, [
        status,
        h(UBadge, {
          'color': SUGGESTION_COLORS[s.value], 'variant': 'outline', 'size': 'sm', 'icon': 'i-lucide-sparkles',
          'label': t('ai.triage.badge', { value: t(`ai.triage.${s.value}`) }), 'title': t('ai.triage.help'), 'data-testid': 'ai-triage-badge',
        }),
      ])
    },
  },
])

// --- Détail et tri ---
const detail = ref<FindingDetail | null>(null)
const detailOpen = ref(false)
const detailLoading = ref(false)
async function openDetail(id: string) {
  detailOpen.value = true
  detailLoading.value = true
  try {
    detail.value = await api<FindingDetail>(`/api/findings/${id}`)
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
    detailOpen.value = false
  }
  finally {
    detailLoading.value = false
  }
}
function onSelect(_e: Event, row: TableRow<FindingRow>) {
  void openDetail(row.original.id)
}

const canTriage = computed(() => session.can('operator'))
const busy = ref<string | null>(null)
async function post(path: string, body: Record<string, unknown>, key: string): Promise<boolean> {
  if (!detail.value) return false
  busy.value = key
  try {
    detail.value = await api<FindingDetail>(`/api/findings/${detail.value.id}/${path}`, { method: 'POST', body })
    toast.add({ title: t('findings.saved'), color: 'success' })
    void reloadAll()
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
const setStatus = (status: 'new' | 'confirmed') => post('status', { status }, status)

// Modale de motif (faux positif) ou de motif + date de fin (acceptation).
const reasonOpen = ref(false)
const reasonMode = ref<'false-positive' | 'accepted'>('false-positive')
const reasonForm = reactive({ reason: '', until: '' })
function isoDay(days: number) {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + days)
  return d.toISOString().slice(0, 10)
}
function askReason(mode: 'false-positive' | 'accepted') {
  reasonMode.value = mode
  reasonForm.reason = ''
  reasonForm.until = isoDay(90)
  reasonOpen.value = true
}
const reasonValid = computed(() => reasonForm.reason.trim().length >= 3
  && (reasonMode.value !== 'accepted' || (/^\d{4}-\d{2}-\d{2}$/.test(reasonForm.until) && reasonForm.until >= isoDay(0) && reasonForm.until <= isoDay(366))))
async function submitReason() {
  const body: Record<string, unknown> = { status: reasonMode.value, reason: reasonForm.reason.trim() }
  if (reasonMode.value === 'accepted') body.until = reasonForm.until
  if (await post('status', body, reasonMode.value)) reasonOpen.value = false
}

const revokeOpen = ref(false)
async function confirmRevoked() {
  if (await post('secret', { state: 'revoked' }, 'revoked')) revokeOpen.value = false
}
const setSecret = (state: 'to-revoke' | 'false-positive') => post('secret', { state }, `secret-${state}`)
</script>

<template>
  <PageShell :title="t('findings.title')">
    <template #actions>
      <UButton
        to="/findings/exceptions"
        icon="i-lucide-shield-off"
        color="neutral"
        variant="ghost"
        :label="t('findings.exceptionsLink')"
      />
      <UButton
        to="/system/severities"
        icon="i-lucide-sliders-horizontal"
        color="neutral"
        variant="ghost"
        :label="t('findings.severitiesLink')"
      />
      <UButton
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="ghost"
        :loading="loading || reloading"
        :aria-label="t('findings.refresh')"
        @click="reloadAll"
      />
    </template>

    <UAlert
      v-if="totals.malicious"
      color="error"
      variant="solid"
      icon="i-lucide-skull"
      :title="t('findings.alerts.malicious', { count: totals.malicious })"
      :actions="[{ label: t('findings.alerts.show'), color: 'neutral', variant: 'outline', onClick: () => { resetFilters(); filters.status = 'all'; filters.malicious = true } }]"
    />
    <UAlert
      v-if="totals.secrets"
      color="warning"
      variant="subtle"
      icon="i-lucide-key-round"
      :title="t('findings.alerts.secrets', { count: totals.secrets })"
      :actions="[{ label: t('findings.alerts.show'), color: 'neutral', variant: 'outline', onClick: () => { resetFilters(); filters.status = 'all'; filters.secret = true } }]"
    />

    <UCard v-if="summary.length > 1 && filters.project_id === 'all'">
      <template #header>
        <h2 class="font-semibold">
          {{ t('findings.byProject.title') }}
        </h2>
      </template>
      <ul class="divide-y divide-default text-sm">
        <li
          v-for="p in summary"
          :key="p.project_id"
          class="flex flex-wrap items-center justify-between gap-2 py-2"
        >
          <UButton
            variant="link"
            :label="p.project_name"
            :aria-label="t('findings.byProject.select')"
            @click="filters.project_id = p.project_id"
          />
          <span class="flex flex-wrap items-center gap-1">
            <UBadge
              v-if="p.malicious"
              color="error"
              variant="solid"
              :label="`${t('findings.badges.malicious')} ${p.malicious}`"
            />
            <FindingsSeverityBadge
              v-for="s in (['critical', 'high', 'medium'] as const).filter(s => p[s] > 0)"
              :key="s"
              :severity="s"
            />
            <span class="text-muted">{{ t('findings.byProject.open') }} : {{ p.open }}</span>
          </span>
        </li>
      </ul>
    </UCard>

    <div class="flex flex-wrap items-end gap-3">
      <UFormField :label="t('findings.filters.project')">
        <USelect
          v-model="filters.project_id"
          :items="projectItems"
          class="w-48"
        />
      </UFormField>
      <UFormField :label="t('findings.filters.severity')">
        <USelect
          v-model="filters.severity"
          :items="severityItems"
          class="w-36"
        />
      </UFormField>
      <UFormField :label="t('findings.filters.category')">
        <USelect
          v-model="filters.category"
          :items="categoryItems"
          class="w-40"
        />
      </UFormField>
      <UFormField :label="t('findings.filters.status')">
        <USelect
          v-model="filters.status"
          :items="statusItems"
          class="w-48"
        />
      </UFormField>
      <UFormField :label="t('findings.filters.tool')">
        <UInput
          v-model="filters.tool"
          class="w-36"
        />
      </UFormField>
      <UFormField
        :label="t('findings.filters.search')"
        class="grow"
      >
        <UInput
          v-model="filters.q"
          icon="i-lucide-search"
          class="w-full"
        />
      </UFormField>
    </div>
    <div class="flex flex-wrap items-center gap-4">
      <UCheckbox
        v-model="filters.is_new"
        :label="t('findings.filters.onlyNew')"
      />
      <UCheckbox
        v-model="filters.secret"
        :label="t('findings.filters.onlySecrets')"
      />
      <UCheckbox
        v-model="filters.malicious"
        :label="t('findings.filters.onlyMalicious')"
      />
      <UButton
        size="xs"
        color="neutral"
        variant="ghost"
        icon="i-lucide-x"
        :label="t('findings.filters.reset')"
        @click="resetFilters"
      />
    </div>

    <UCard>
      <p class="mb-2 text-xs text-muted">
        {{ t('findings.total', { total }) }} · {{ t('findings.clickHint') }}
      </p>
      <UTable
        :data="items"
        :columns="columns"
        :loading="loading"
        :empty="t('common.none')"
        class="cursor-pointer"
        @select="onSelect"
      />
      <div
        v-if="total > PAGE"
        class="mt-4 flex justify-end"
      >
        <UPagination
          v-model:page="page"
          :total="total"
          :items-per-page="PAGE"
        />
      </div>
    </UCard>

    <USlideover
      v-model:open="detailOpen"
      :title="t('findings.detail.title')"
      side="right"
      :ui="{ content: 'max-w-2xl' }"
    >
      <template #body>
        <div
          v-if="detailLoading && !detail"
          class="flex justify-center py-8"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-6 animate-spin"
          />
        </div>
        <div
          v-else-if="detail"
          class="space-y-4 text-sm"
          data-testid="finding-detail"
        >
          <div class="flex flex-wrap items-center gap-2">
            <FindingsSeverityBadge :severity="detail.severity" />
            <UBadge
              :color="statusColor(detail.status)"
              variant="subtle"
              :label="t(`findings.status.${detail.status}`)"
            />
            <UBadge
              v-if="detail.is_new"
              color="info"
              variant="subtle"
              :label="t('findings.badges.new')"
            />
          </div>
          <h3 class="text-base font-semibold break-words">
            {{ detail.title }}
          </h3>

          <UAlert
            v-if="detail.malicious"
            color="error"
            variant="solid"
            icon="i-lucide-skull"
            :title="t('findings.detail.maliciousHelp')"
          />
          <UAlert
            v-if="detail.accepted_expired"
            color="warning"
            variant="subtle"
            :title="t('findings.detail.acceptedExpired')"
          />

          <dl class="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <dt class="text-muted">
                {{ t('findings.columns.project') }}
              </dt>
              <dd>{{ detail.project_name }}</dd>
            </div>
            <div>
              <dt class="text-muted">
                {{ t('findings.detail.tool') }} · {{ t('findings.detail.rule') }}
              </dt>
              <dd class="font-mono text-xs break-all">
                {{ detail.tool }} · {{ detail.rule_id }}
              </dd>
            </div>
            <div>
              <dt class="text-muted">
                {{ t('findings.detail.category') }}
              </dt>
              <dd>{{ categoryLabel(detail.category) }}</dd>
            </div>
            <div>
              <dt class="text-muted">
                {{ t('findings.detail.nativeSeverity') }}
              </dt>
              <dd class="font-mono text-xs">
                {{ detail.native_severity ?? '—' }}
              </dd>
            </div>
            <div v-if="detail.path">
              <dt class="text-muted">
                {{ t('findings.detail.location') }}
              </dt>
              <dd class="font-mono text-xs break-all">
                {{ detail.path }}<span v-if="detail.start_line">:{{ detail.start_line }}<span v-if="detail.end_line && detail.end_line !== detail.start_line">-{{ detail.end_line }}</span></span>
              </dd>
            </div>
            <div v-if="detail.package">
              <dt class="text-muted">
                {{ t('findings.detail.package') }}
              </dt>
              <dd class="font-mono text-xs break-all">
                {{ detail.package.ecosystem ? `${detail.package.ecosystem} · ` : '' }}{{ detail.package.name }}@{{ detail.package.version ?? '?' }}
                <span class="block text-muted">{{ detail.package.fixed.length ? t('findings.detail.fixedIn', { versions: detail.package.fixed.join(', ') }) : t('findings.detail.noFix') }}</span>
              </dd>
            </div>
            <div v-if="detail.vuln_ids.length">
              <dt class="text-muted">
                {{ t('findings.detail.advisories') }}
              </dt>
              <dd class="font-mono text-xs">
                {{ detail.vuln_ids.join(', ') }}
              </dd>
            </div>
            <div v-if="detail.cwe.length">
              <dt class="text-muted">
                {{ t('findings.detail.cwe') }}
              </dt>
              <dd class="font-mono text-xs">
                {{ detail.cwe.join(', ') }}
              </dd>
            </div>
            <div>
              <dt class="text-muted">
                {{ t('findings.detail.firstSeen') }}
              </dt>
              <dd>{{ fmt.date(detail.first_seen_at) }}</dd>
            </div>
            <div v-if="detail.first_commit || detail.last_commit">
              <dt class="text-muted">
                {{ t('findings.detail.commits') }}
              </dt>
              <dd class="font-mono text-xs">
                {{ detail.first_commit?.slice(0, 12) ?? '—' }} → {{ detail.last_commit?.slice(0, 12) ?? '—' }}
              </dd>
            </div>
          </dl>

          <div v-if="detail.message">
            <p class="text-muted">
              {{ t('findings.detail.message') }}
            </p>
            <p class="mt-1 whitespace-pre-wrap break-words">
              {{ detail.message }}
            </p>
          </div>
          <div v-if="detail.snippet">
            <p class="text-muted">
              {{ t('findings.detail.snippet') }}
            </p>
            <pre class="mt-1 max-h-64 overflow-auto rounded bg-muted p-3 font-mono text-xs">{{ detail.snippet }}</pre>
          </div>

          <FindingsFindingAi
            :finding-id="detail.id"
            :project-id="detail.project_id"
            :status="detail.status"
            :title="detail.title"
            :secret="!!detail.secret_type"
          />

          <UCard v-if="detail.secret_type">
            <template #header>
              <h4 class="font-semibold">
                {{ t('findings.detail.secretTitle') }} · <span class="font-mono text-xs">{{ detail.secret_type }}</span>
              </h4>
            </template>
            <div class="space-y-3">
              <UBadge
                :color="detail.secret_state === 'to-revoke' ? 'warning' : 'neutral'"
                variant="subtle"
                :label="t(`findings.secretState.${detail.secret_state ?? 'to-revoke'}`)"
              />
              <UAlert
                v-if="detail.revoke_pending_days !== null"
                color="warning"
                variant="subtle"
                icon="i-lucide-bell-ring"
                :title="t('findings.detail.secretPending', { days: detail.revoke_pending_days })"
              />
              <p
                v-if="detail.secret_state_by && detail.secret_state !== 'to-revoke'"
                class="text-muted"
              >
                {{ t('findings.detail.secretBy', { state: t(`findings.secretState.${detail.secret_state}`), user: detail.secret_state_by, date: fmt.date(detail.secret_state_at) }) }}
              </p>
              <p class="text-xs text-muted">
                {{ t('findings.detail.secretHelp') }}
              </p>
              <AiSecretClass :finding-id="detail.id" />
              <div
                v-if="canTriage"
                class="flex flex-wrap gap-2"
              >
                <UButton
                  v-if="detail.secret_state !== 'revoked'"
                  icon="i-lucide-shield-check"
                  :label="t('findings.actions.revoked')"
                  :loading="busy === 'revoked'"
                  @click="revokeOpen = true"
                />
                <UButton
                  v-if="detail.secret_state !== 'false-positive'"
                  color="neutral"
                  variant="outline"
                  :label="t('findings.actions.secretFalsePositive')"
                  :loading="busy === 'secret-false-positive'"
                  @click="setSecret('false-positive')"
                />
                <UButton
                  v-if="detail.secret_state !== 'to-revoke'"
                  color="neutral"
                  variant="ghost"
                  :label="t('findings.actions.secretReopen')"
                  :loading="busy === 'secret-to-revoke'"
                  @click="setSecret('to-revoke')"
                />
              </div>
            </div>
          </UCard>

          <div>
            <p class="text-muted">
              {{ t('findings.detail.triage') }}
            </p>
            <p v-if="detail.status_by">
              {{ t(`findings.status.${detail.status}`) }} {{ t('findings.detail.statusBy', { user: detail.status_by, date: fmt.date(detail.status_at) }) }}
              <span v-if="detail.status_until"> · {{ t('findings.detail.until', { date: detail.status_until }) }}</span>
            </p>
            <p
              v-if="detail.status_reason"
              class="whitespace-pre-wrap break-words"
            >
              {{ t('findings.detail.reason') }} : {{ detail.status_reason }}
            </p>
            <div
              v-if="canTriage && detail.status !== 'fixed'"
              class="mt-2 flex flex-wrap gap-2"
            >
              <UButton
                v-if="detail.status !== 'confirmed'"
                color="error"
                variant="outline"
                :label="t('findings.actions.confirm')"
                :loading="busy === 'confirmed'"
                @click="setStatus('confirmed')"
              />
              <UButton
                v-if="!detail.malicious && detail.status !== 'false-positive'"
                color="neutral"
                variant="outline"
                :label="t('findings.actions.falsePositive')"
                @click="askReason('false-positive')"
              />
              <UButton
                v-if="!detail.malicious && detail.status !== 'accepted'"
                color="neutral"
                variant="outline"
                :label="t('findings.actions.accept')"
                @click="askReason('accepted')"
              />
              <UButton
                v-if="detail.status !== 'new'"
                color="neutral"
                variant="ghost"
                :label="t('findings.actions.reopen')"
                :loading="busy === 'new'"
                @click="setStatus('new')"
              />
              <UButton
                v-if="!detail.malicious"
                color="neutral"
                variant="ghost"
                icon="i-lucide-shield-off"
                :to="`/findings/exceptions?project_id=${detail.project_id}&finding_id=${detail.id}`"
                :label="t('findings.actions.createException')"
              />
            </div>
          </div>

          <div v-if="detail.scans.length">
            <p class="text-muted">
              {{ t('findings.detail.scans') }}
            </p>
            <ul class="mt-1 space-y-1">
              <li
                v-for="s in detail.scans"
                :key="s.id"
                class="flex items-center gap-2"
              >
                <ULink
                  :to="`/scans/${s.id}`"
                  class="font-mono text-xs"
                >
                  {{ t('findings.detail.scanLine', { number: s.number, ref: s.ref }) }}
                </ULink>
                <span class="text-xs text-muted">{{ fmt.date(s.queued_at) }}</span>
                <UBadge
                  v-if="s.is_new"
                  size="sm"
                  color="info"
                  variant="subtle"
                  :label="t('findings.detail.newInScan')"
                />
              </li>
            </ul>
          </div>
          <p class="font-mono text-[10px] text-muted break-all">
            {{ t('findings.detail.fingerprint') }} : {{ detail.fingerprint }}
          </p>
        </div>
      </template>
    </USlideover>

    <UModal
      v-model:open="reasonOpen"
      :title="reasonMode === 'accepted' ? t('findings.modal.acceptTitle') : t('findings.modal.falsePositiveTitle')"
      :dismissible="!busy"
    >
      <template #body>
        <div class="space-y-4">
          <p
            v-if="reasonMode === 'accepted'"
            class="text-sm text-muted"
          >
            {{ t('findings.modal.acceptHelp') }}
          </p>
          <UFormField :label="t('findings.modal.reason')">
            <UTextarea
              v-model="reasonForm.reason"
              :maxlength="2000"
              class="w-full"
              data-testid="reason"
            />
          </UFormField>
          <UFormField
            v-if="reasonMode === 'accepted'"
            :label="t('findings.modal.until')"
          >
            <UInput
              v-model="reasonForm.until"
              type="date"
              data-testid="until"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="!!busy"
            :label="t('common.cancel')"
            @click="reasonOpen = false"
          />
          <UButton
            :loading="!!busy"
            :disabled="!reasonValid"
            :label="t('common.confirm')"
            @click="submitReason"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="revokeOpen"
      :title="t('findings.modal.revokedTitle')"
      :body="t('findings.modal.revokedBody')"
      :loading="busy === 'revoked'"
      @confirm="confirmRevoked"
    />
  </PageShell>
</template>
