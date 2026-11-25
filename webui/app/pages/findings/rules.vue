<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Règles de tri en masse (F4) : chemin (glob), outil, règle et gravités →
faux positif, confirmé ou accepté, avec justification et date de fin
obligatoires. L'effet est TOUJOURS simulé avant l'enregistrement (résultats
touchés par projet, et liste) ; « Enregistrer » ne s'active qu'après une
simulation du formulaire tel qu'il est. Une règle « accepté » vaut une
exception approuvée : administrateur seulement. Les propositions de l'IA
(I3, et I7 depuis les résultats semblables) pré-remplissent le formulaire,
sans rien enregistrer : l'enregistrement reste un clic d'une personne.
Liens directs : ?project_id=…&tool=…&rule=…&path=…&action=…&reason=… ouvre la
création pré-remplie ; ?rule=<id> met une règle en évidence.
-->

<script setup lang="ts">
import { SEVERITIES } from '#shared/analysis'

type Sev = typeof SEVERITIES[number]

const { t } = useI18n()
useHead({ title: computed(() => t('triage.rules.title')) })

const route = useRoute()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()

type Action = 'false-positive' | 'accepted' | 'confirmed'
interface Match { path?: string, tool?: string, rule?: string, severity?: string[] }
interface RuleRow {
  id: string
  project_id: string | null
  project_slug: string | null
  match: Match
  action: Action
  reason: string
  expires_on: string
  applied_count: number
  created_by: string | null
  created_at: string
  revoked_at: string | null
  active: boolean
}
interface Simulation {
  total: number
  projects: { project_id: string, project_slug: string, count: number }[]
  items: { id: string, project_slug: string, tool: string, rule_id: string, severity: string, path: string | null, title: string }[]
  truncated: boolean
}
interface Proposal { project_id: string, match: Match, action: Action, reason_kind: string, count: number, reason: string }

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const str = (v: unknown) => (typeof v === 'string' ? v : '')

const projects = ref<{ project_id: string, project_name: string }[]>([])
const ALL = 'all'
const projectId = ref(UUID.test(str(route.query.project_id)) ? str(route.query.project_id) : ALL)
const showAll = ref(false)
const rules = ref<RuleRow[]>([])
const proposals = ref<Proposal[]>([])
const loading = ref(false)
const loadError = ref('')
const highlight = str(route.query.rule)
const canEdit = computed(() => session.can('operator'))
const isAdmin = computed(() => session.can('admin'))

async function loadProjects() {
  try {
    projects.value = (await api<{ projects: { project_id: string, project_name: string }[] }>('/api/findings/summary')).projects
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
}
async function load() {
  loading.value = true
  try {
    const query: Record<string, unknown> = {}
    if (projectId.value !== ALL) query.project_id = projectId.value
    if (showAll.value) query.all = 'true'
    rules.value = (await api<{ items: RuleRow[] }>('/api/triage-rules', { query })).items
    proposals.value = projectId.value !== ALL
      ? (await api<{ items: Proposal[] }>('/api/triage-rules/proposals', { query: { project_id: projectId.value } })).items
      : []
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
watch([projectId, showAll], load)
onMounted(async () => {
  await loadProjects()
  await load()
  const q = route.query
  if (canEdit.value && (q.tool || q.rule || q.path)) {
    openCreate({
      match: { tool: str(q.tool) || undefined, rule: str(q.rule) || undefined, path: str(q.path) || undefined },
      action: (['false-positive', 'confirmed'] as const).find(a => a === q.action) ?? 'false-positive',
      reason: str(q.reason).slice(0, 2000),
    })
  }
})

const projectItems = computed(() => [
  { label: t('triage.rules.allProjects'), value: ALL },
  ...projects.value.map(p => ({ label: p.project_name, value: p.project_id })),
])
// « accepted » n'est plus une action de règle : accepter passe par une demande d'exception approuvée (F5, J15).
const actionItems = computed(() => (['false-positive', 'confirmed'] as Action[])
  .map(a => ({ label: t(`findings.status.${a}`), value: a })))
const severityItems = computed(() => SEVERITIES.map(s => ({ label: t(`findings.severity.${s}`), value: s })))

function matchText(m: Match): string {
  const parts: string[] = []
  if (m.path) parts.push(`${t('triage.rules.fields.path')} ${m.path}`)
  if (m.tool) parts.push(`${t('triage.rules.fields.tool')} ${m.tool}`)
  if (m.rule) parts.push(`${t('triage.rules.fields.rule')} ${m.rule}`)
  if (m.severity?.length) parts.push(m.severity.map(s => t(`findings.severity.${s}`)).join(', '))
  return parts.join(' · ')
}

// --- Création, simulation obligatoire ---
function isoDay(days: number) {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + days)
  return d.toISOString().slice(0, 10)
}
const createOpen = ref(false)
const form = reactive<{ project_id: string, path: string, tool: string, rule: string, severity: Sev[], action: Action, reason: string, expires_on: string, fromAi: boolean }>({
  project_id: ALL, path: '', tool: '', rule: '', severity: [], action: 'false-positive', reason: '', expires_on: isoDay(90), fromAi: false,
})
function openCreate(pre: { match?: Match, action?: Action, reason?: string, project_id?: string, fromAi?: boolean } = {}) {
  Object.assign(form, {
    project_id: pre.project_id ?? projectId.value,
    path: pre.match?.path ?? '', tool: pre.match?.tool ?? '', rule: pre.match?.rule ?? '', severity: (pre.match?.severity ?? []).filter((x): x is Sev => (SEVERITIES as readonly string[]).includes(x)),
    action: pre.action ?? 'false-positive', reason: pre.reason ?? '', expires_on: isoDay(90), fromAi: pre.fromAi ?? false,
  })
  simulation.value = null
  simulatedKey.value = ''
  createOpen.value = true
}
function body() {
  const match: Match = {}
  if (form.path.trim()) match.path = form.path.trim()
  if (form.tool.trim()) match.tool = form.tool.trim()
  if (form.rule.trim()) match.rule = form.rule.trim()
  if (form.severity.length) match.severity = [...form.severity]
  return { project_id: form.project_id === ALL ? null : form.project_id, match, action: form.action, reason: form.reason.trim(), expires_on: form.expires_on }
}
const formKey = computed(() => JSON.stringify(body()))
const formValid = computed(() => {
  const b = body()
  return Object.keys(b.match).length > 0 && b.reason.length >= 3 && /^\d{4}-\d{2}-\d{2}$/.test(b.expires_on)
    && b.expires_on >= isoDay(0) && b.expires_on <= isoDay(366) && (b.project_id !== null || isAdmin.value)
})
const simulation = ref<Simulation | null>(null)
const simulatedKey = ref('')
const simulating = ref(false)
const saving = ref(false)
async function simulate() {
  simulating.value = true
  try {
    const key = formKey.value
    simulation.value = await api<Simulation>('/api/triage-rules/simulate', { method: 'POST', body: body() })
    simulatedKey.value = key
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    simulating.value = false
  }
}
const canSave = computed(() => formValid.value && !!simulation.value && simulatedKey.value === formKey.value)
async function save() {
  saving.value = true
  try {
    const r = await api<{ applied: number }>('/api/triage-rules', { method: 'POST', body: body() })
    toast.add({ title: t('triage.rules.saved', { count: r.applied }), color: 'success' })
    createOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

// --- Révocation ---
const revokeTarget = ref<RuleRow | null>(null)
const revokeOpen = ref(false)
const revoking = ref(false)
async function revoke() {
  if (!revokeTarget.value) return
  revoking.value = true
  try {
    const r = await api<{ reverted: number }>(`/api/triage-rules/${revokeTarget.value.id}`, { method: 'DELETE' })
    toast.add({ title: t('triage.rules.revoked', { count: r.reverted }), color: 'success' })
    revokeOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    revoking.value = false
  }
}
function canRevoke(r: RuleRow) {
  return r.active && canEdit.value && (isAdmin.value || (r.action !== 'accepted' && r.project_id !== null))
}
</script>

<template>
  <PageShell :title="t('triage.rules.title')">
    <template #actions>
      <UButton
        to="/findings"
        icon="i-lucide-list-checks"
        color="neutral"
        variant="ghost"
        :label="t('findings.title')"
      />
      <UButton
        v-if="isAdmin"
        to="/findings/owners"
        icon="i-lucide-users-round"
        color="neutral"
        variant="ghost"
        :label="t('triage.owners.nav')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('triage.rules.help') }}
    </p>
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />

    <div class="flex flex-wrap items-end gap-3">
      <UFormField :label="t('findings.filters.project')">
        <USelect
          v-model="projectId"
          :items="projectItems"
          class="w-60"
        />
      </UFormField>
      <UCheckbox
        v-model="showAll"
        :label="t('triage.rules.showAll')"
      />
      <UButton
        v-if="canEdit"
        icon="i-lucide-plus"
        :label="t('triage.rules.create')"
        data-testid="rule-create"
        @click="openCreate()"
      />
    </div>

    <UCard v-if="proposals.length">
      <template #header>
        <div class="flex items-center gap-2 font-semibold">
          <UIcon name="i-lucide-sparkles" />
          {{ t('triage.rules.proposals') }}
          <UBadge
            color="neutral"
            variant="subtle"
            :label="t('triage.rules.proposedByAi')"
          />
        </div>
      </template>
      <ul class="divide-y divide-default text-sm">
        <li
          v-for="(p, i) in proposals"
          :key="i"
          class="flex flex-wrap items-center justify-between gap-2 py-2"
          data-testid="proposal"
        >
          <div class="min-w-0">
            <p class="font-mono text-xs break-all">
              {{ matchText(p.match) }}
            </p>
            <p class="text-xs text-muted">
              {{ t('triage.rules.proposalCount', { count: p.count, reason: t(`ai.triage.reasons.${p.reason_kind}`) }) }}
            </p>
          </div>
          <UButton
            v-if="canEdit"
            size="xs"
            variant="outline"
            :label="t('triage.rules.prefill')"
            @click="openCreate({ match: p.match, action: p.action, reason: p.reason, project_id: p.project_id, fromAi: true })"
          />
        </li>
      </ul>
    </UCard>

    <UCard>
      <div
        v-if="loading"
        class="flex justify-center py-6"
      >
        <UIcon
          name="i-lucide-loader-circle"
          class="size-6 animate-spin"
        />
      </div>
      <p
        v-else-if="!rules.length"
        class="text-sm text-muted"
      >
        {{ t('triage.rules.none') }}
      </p>
      <ul
        v-else
        class="divide-y divide-default text-sm"
      >
        <li
          v-for="r in rules"
          :key="r.id"
          class="flex flex-wrap items-start justify-between gap-3 py-3"
          :class="r.id === highlight ? 'bg-elevated' : ''"
          data-testid="rule"
        >
          <div class="min-w-0 space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <UBadge
                variant="subtle"
                :color="r.action === 'confirmed' ? 'error' : r.action === 'accepted' ? 'warning' : 'neutral'"
                :label="t(`findings.status.${r.action}`)"
              />
              <span class="font-mono text-xs break-all">{{ matchText(r.match) }}</span>
              <UBadge
                variant="subtle"
                color="neutral"
                :label="r.project_slug ?? t('triage.rules.global')"
              />
              <UBadge
                v-if="!r.active"
                variant="subtle"
                color="neutral"
                :label="r.revoked_at ? t('findings.exceptions.revoked') : t('findings.exceptions.expired')"
              />
            </div>
            <p class="whitespace-pre-wrap break-words">
              {{ r.reason }}
            </p>
            <p class="text-xs text-muted">
              {{ t('findings.exceptions.expires') }} : {{ r.expires_on }} · {{ t('triage.rules.applied', { count: r.applied_count }) }} · {{ r.created_by ?? '—' }}, {{ fmt.date(r.created_at) }}
            </p>
          </div>
          <UButton
            v-if="canRevoke(r)"
            color="error"
            variant="ghost"
            icon="i-lucide-ban"
            :label="t('findings.exceptions.revoke')"
            @click="revokeTarget = r; revokeOpen = true"
          />
        </li>
      </ul>
    </UCard>

    <UModal
      v-model:open="createOpen"
      :title="t('triage.rules.create')"
      :dismissible="!saving && !simulating"
      :ui="{ content: 'max-w-2xl' }"
    >
      <template #body>
        <div class="space-y-4">
          <UAlert
            v-if="form.fromAi"
            color="neutral"
            variant="subtle"
            icon="i-lucide-sparkles"
            :title="t('triage.rules.fromAi')"
          />
          <UFormField :label="t('findings.filters.project')">
            <USelect
              v-model="form.project_id"
              :items="isAdmin ? projectItems : projectItems.filter(p => p.value !== ALL)"
              class="w-60"
            />
          </UFormField>
          <div class="grid gap-3 sm:grid-cols-2">
            <UFormField
              :label="t('triage.rules.fields.path')"
              :help="t('triage.rules.pathHelp')"
            >
              <UInput
                v-model="form.path"
                class="w-full font-mono"
                data-testid="rule-path"
              />
            </UFormField>
            <UFormField :label="t('triage.rules.fields.tool')">
              <UInput
                v-model="form.tool"
                class="w-full font-mono"
                data-testid="rule-tool"
              />
            </UFormField>
            <UFormField :label="t('triage.rules.fields.rule')">
              <UInput
                v-model="form.rule"
                class="w-full font-mono"
                data-testid="rule-rule"
              />
            </UFormField>
            <UFormField :label="t('triage.rules.fields.severity')">
              <USelectMenu
                v-model="form.severity"
                :items="severityItems"
                value-key="value"
                multiple
                class="w-full"
              />
            </UFormField>
          </div>
          <UFormField :label="t('triage.rules.fields.action')">
            <USelect
              v-model="form.action"
              :items="actionItems"
              class="w-60"
              data-testid="rule-action"
            />
          </UFormField>
          <UFormField :label="t('findings.modal.reason')">
            <UTextarea
              v-model="form.reason"
              :maxlength="2000"
              class="w-full"
              data-testid="rule-reason"
            />
          </UFormField>
          <UFormField :label="t('findings.modal.until')">
            <UInput
              v-model="form.expires_on"
              type="date"
            />
          </UFormField>

          <div
            v-if="simulation && simulatedKey === formKey"
            class="space-y-2 rounded-md border border-default p-3 text-sm"
            data-testid="simulation"
          >
            <p class="font-medium">
              {{ t('triage.rules.simulated', { count: simulation.total }) }}
            </p>
            <ul class="text-xs">
              <li
                v-for="p in simulation.projects"
                :key="p.project_id"
              >
                {{ p.project_slug }} : {{ p.count }}
              </li>
            </ul>
            <ul class="max-h-48 overflow-auto font-mono text-xs">
              <li
                v-for="f in simulation.items"
                :key="f.id"
                class="break-all"
              >
                {{ f.project_slug }} · {{ f.tool }} · {{ f.rule_id }} · {{ f.path ?? '—' }}
              </li>
            </ul>
            <p
              v-if="simulation.truncated"
              class="text-xs text-muted"
            >
              {{ t('triage.rules.truncated') }}
            </p>
          </div>
          <p
            v-else
            class="text-xs text-muted"
          >
            {{ t('triage.rules.simulateFirst') }}
          </p>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="saving || simulating"
            :label="t('common.cancel')"
            @click="createOpen = false"
          />
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-flask-conical"
            :loading="simulating"
            :disabled="!formValid || saving"
            :label="t('triage.rules.simulate')"
            data-testid="rule-simulate"
            @click="simulate"
          />
          <UButton
            :loading="saving"
            :disabled="!canSave || simulating"
            :label="t('triage.rules.save')"
            data-testid="rule-save"
            @click="save"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="revokeOpen"
      :title="t('triage.rules.revokeTitle')"
      :body="t('triage.rules.revokeBody')"
      color="error"
      :loading="revoking"
      @confirm="revoke"
    />
  </PageShell>
</template>
