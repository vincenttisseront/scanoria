<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Exceptions d'un projet (§ 6.1), soumises à approbation (F5, J15) : un
opérateur DEMANDE (motif et date de fin obligatoires, un an au plus), un
autre administrateur approuve ou refuse (page « Exceptions à approuver »).
Une demande ne compte pour le gate qu'une fois approuvée. Échues d'elles-mêmes,
révocables (modale de la console), avec un bandeau d'échéance. Refusée par le
serveur pour un avis MAL- ou un résultat malveillant (H4) et contre un verrou
de profil (G8). I10 : motif proposé par l'IA pour un résultat, à relire.
Liens directs (cible des statuts et commentaires de forge, J15) :
/projects/:id/exceptions/new?finding=…[&scan=…] et
/findings/exceptions?project_id=…&finding_id=…
-->

<script setup lang="ts">
import { EXCEPTION_KINDS } from '#shared/analysis'

definePageMeta({ alias: ['/projects/:id/exceptions/new'] })

const { t } = useI18n()
useHead({ title: computed(() => t('findings.exceptions.title')) })

const route = useRoute()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()

type Kind = (typeof EXCEPTION_KINDS)[number]
interface ExceptionRow {
  id: string
  project_id: string
  kind: Kind
  target: Record<string, string>
  reason: string
  expires_on: string
  status: 'requested' | 'approved' | 'refused'
  requested_via: string
  requester_label: string | null
  requester_is_human: boolean
  created_by: string | null
  created_at: string
  decided_by: string | null
  decided_at: string | null
  decision_reason: string | null
  revoked_at: string | null
  revoked_by: string | null
  active: boolean
  expired: boolean
  expiring_soon: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const qs = (v: unknown) => (typeof v === 'string' && UUID.test(v) ? v : '')
const routeProject = qs(route.params.id) || qs(route.query.project_id)
const routeFinding = qs(route.query.finding) || qs(route.query.finding_id)
const routeScan = qs(route.query.scan) || qs(route.query.scan_id)

const projects = ref<{ project_id: string, project_name: string }[]>([])
const projectId = ref(routeProject)
const showAll = ref(false)
const items = ref<ExceptionRow[]>([])
const loading = ref(false)
const canEdit = computed(() => session.can('operator'))

async function loadProjects() {
  try {
    projects.value = (await api<{ projects: { project_id: string, project_name: string }[] }>('/api/findings/summary')).projects
    if (!projectId.value && projects.value.length === 1) projectId.value = projects.value[0]!.project_id
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
}
const loadError = ref('')
async function load() {
  if (!projectId.value) {
    items.value = []
    return
  }
  loading.value = true
  try {
    const query: Record<string, unknown> = { project_id: projectId.value }
    if (showAll.value) query.all = 'true'
    items.value = (await api<{ items: ExceptionRow[] }>('/api/exceptions', { query })).items
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(async () => {
  await loadProjects()
  await load()
  if (routeFinding && canEdit.value) openCreate('finding', { finding_id: routeFinding })
})
watch([projectId, showAll], load)

const expiring = computed(() => items.value.filter(e => e.expiring_soon))

const projectItems = computed(() => projects.value.map(p => ({ label: p.project_name, value: p.project_id })))
const kindItems = computed(() => EXCEPTION_KINDS.map(k => ({ label: t(`findings.exceptions.kinds.${k}`), value: k })))

/** Champs de la cible par type (ExceptionTargets de #shared/analysis). */
const FIELDS: Record<Kind, { key: string, label: string, optional?: boolean }[]> = {
  path: [{ key: 'glob', label: 'glob' }, { key: 'tool', label: 'tool', optional: true }],
  rule: [{ key: 'rule_id', label: 'ruleId' }, { key: 'tool', label: 'tool', optional: true }],
  vuln: [{ key: 'vuln_id', label: 'vulnId' }, { key: 'package', label: 'package', optional: true }],
  finding: [{ key: 'finding_id', label: 'findingId' }],
  module: [{ key: 'module_id', label: 'moduleId' }],
}

function targetText(e: ExceptionRow): string {
  return Object.entries(e.target).map(([k, v]) => `${k}=${v}`).join(' · ')
}
function stateOf(e: ExceptionRow): { label: string, color: 'success' | 'neutral' | 'warning' | 'info' | 'error' } {
  if (e.revoked_at) return { label: t('findings.exceptions.revoked'), color: 'neutral' }
  if (e.status === 'refused') return { label: t('triage.approvals.state.refused'), color: 'error' }
  if (e.expired) return { label: t('findings.exceptions.expired'), color: 'warning' }
  if (e.status === 'requested') return { label: t('triage.approvals.state.requested'), color: 'info' }
  return { label: t('findings.exceptions.active'), color: 'success' }
}
function requester(e: ExceptionRow): string {
  const who = e.created_by ?? e.requester_label ?? '—'
  return e.requester_is_human === false ? `${who} (${t('triage.approvals.nonHuman')})` : who
}

// --- Demande ---
function isoDay(days: number) {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + days)
  return d.toISOString().slice(0, 10)
}
const createOpen = ref(false)
const saving = ref(false)
/** H7 (0.8) : statut VEX proposé avec la demande (vulnérabilité ou résultat seulement). */
const VEX_NONE = '__none__'
const VEX_VALUES = ['not_affected', 'affected', 'fixed', 'under_investigation'] as const
const vexItems = computed(() => [
  { label: t('vex.statusNone'), value: VEX_NONE },
  ...VEX_VALUES.map(v => ({ label: t(`vex.status.${v}`), value: v })),
])
const form = reactive<{ kind: Kind, target: Record<string, string>, reason: string, expires_on: string, vex_status: string }>({
  kind: 'path', target: {}, reason: '', expires_on: isoDay(90), vex_status: VEX_NONE,
})
const vexAllowed = computed(() => form.kind === 'vuln' || form.kind === 'finding')
function openCreate(kind: Kind = 'path', target: Record<string, string> = {}) {
  Object.assign(form, { kind, target: { ...target }, reason: '', expires_on: isoDay(90), vex_status: VEX_NONE })
  createOpen.value = true
}
function changeKind(kind: Kind) {
  form.kind = kind
  form.target = {}
}
/**
 * I10 : motif proposé recopié, à relire ; la durée est bornée à un an. Depuis
 * la 0.8, le statut VEX proposé est présélectionné et la justification OpenVEX
 * placée en tête du motif (« [justification] »), où la personne la relit.
 */
function useDraft(d: { reason: string, days: number, vex_status?: string | null, vex_justification?: string | null }) {
  const head = d.vex_status === 'not_affected' && d.vex_justification ? `[${d.vex_justification}] ` : ''
  form.reason = `${head}${d.reason}`.slice(0, 2000)
  form.expires_on = isoDay(Math.min(366, Math.max(1, Math.round(d.days))))
  if (vexAllowed.value) form.vex_status = d.vex_status && (VEX_VALUES as readonly string[]).includes(d.vex_status) ? d.vex_status : VEX_NONE
}
const draftFinding = computed(() => (form.kind === 'finding' && UUID.test(form.target.finding_id ?? '') ? form.target.finding_id! : ''))
const createValid = computed(() => form.reason.trim().length >= 3
  && /^\d{4}-\d{2}-\d{2}$/.test(form.expires_on) && form.expires_on >= isoDay(0) && form.expires_on <= isoDay(366)
  && FIELDS[form.kind].every(f => f.optional || (form.target[f.key] ?? '').trim().length > 0))
async function create() {
  saving.value = true
  try {
    const target: Record<string, string> = {}
    for (const f of FIELDS[form.kind]) {
      const v = (form.target[f.key] ?? '').trim()
      if (v) target[f.key] = v
    }
    const body: Record<string, unknown> = { project_id: projectId.value, kind: form.kind, target, reason: form.reason.trim(), expires_on: form.expires_on }
    if (routeScan) body.scan_id = routeScan
    if (vexAllowed.value && form.vex_status !== VEX_NONE) body.vex_status = form.vex_status
    await api('/api/exceptions', { method: 'POST', body })
    toast.add({ title: t('triage.approvals.requested'), color: 'success' })
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
const revokeTarget = ref<ExceptionRow | null>(null)
const revokeOpen = ref(false)
const revoking = ref(false)
function askRevoke(e: ExceptionRow) {
  revokeTarget.value = e
  revokeOpen.value = true
}
async function revoke() {
  if (!revokeTarget.value) return
  revoking.value = true
  try {
    await api(`/api/exceptions/${revokeTarget.value.id}`, { method: 'DELETE' })
    toast.add({ title: t('findings.exceptions.revokedDone'), color: 'success' })
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
</script>

<template>
  <PageShell :title="t('findings.exceptions.title')">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <template #actions>
      <UButton
        v-if="session.can('admin')"
        to="/findings/approvals"
        icon="i-lucide-stamp"
        color="neutral"
        variant="ghost"
        :label="t('triage.approvals.nav')"
      />
      <UButton
        to="/findings"
        icon="i-lucide-list-checks"
        color="neutral"
        variant="ghost"
        :label="t('findings.title')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('triage.approvals.help') }}
    </p>

    <UAlert
      v-if="expiring.length"
      color="warning"
      variant="subtle"
      icon="i-lucide-calendar-clock"
      :title="t('triage.approvals.expiringTitle', { count: expiring.length })"
      :description="expiring.map(e => `${targetText(e)} : ${e.expires_on}`).join(' · ')"
      data-testid="expiring-banner"
    />

    <div class="flex flex-wrap items-end gap-3">
      <UFormField :label="t('findings.filters.project')">
        <USelect
          v-model="projectId"
          :items="projectItems"
          :placeholder="t('findings.exceptions.chooseProject')"
          class="w-60"
        />
      </UFormField>
      <UCheckbox
        v-model="showAll"
        :label="t('findings.exceptions.showAll')"
      />
      <UButton
        v-if="canEdit && projectId"
        icon="i-lucide-plus"
        :label="t('triage.approvals.request')"
        data-testid="exception-request"
        @click="openCreate()"
      />
    </div>

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
        v-else-if="!projectId"
        class="text-sm text-muted"
      >
        {{ t('findings.exceptions.chooseProject') }}
      </p>
      <p
        v-else-if="!items.length"
        class="text-sm text-muted"
      >
        {{ t('findings.exceptions.none') }}
      </p>
      <ul
        v-else
        class="divide-y divide-default text-sm"
      >
        <li
          v-for="e in items"
          :key="e.id"
          class="flex flex-wrap items-start justify-between gap-3 py-3"
          data-testid="exception"
        >
          <div class="min-w-0 space-y-1">
            <div class="flex flex-wrap items-center gap-2">
              <UBadge
                variant="subtle"
                color="neutral"
                :label="t(`findings.exceptions.kinds.${e.kind}`)"
              />
              <span class="font-mono text-xs break-all">{{ targetText(e) }}</span>
              <UBadge
                variant="subtle"
                :color="stateOf(e).color"
                :label="stateOf(e).label"
                data-testid="exception-state"
              />
            </div>
            <p class="whitespace-pre-wrap break-words">
              {{ e.reason }}
            </p>
            <p class="text-xs text-muted">
              {{ t('findings.exceptions.expires') }} : {{ e.expires_on }} · {{ t('triage.approvals.requestedBy', { who: requester(e), via: t(`triage.approvals.via.${e.requested_via ?? 'console'}`), date: fmt.date(e.created_at) }) }}
            </p>
            <p
              v-if="e.decided_by && e.decided_at"
              class="text-xs text-muted"
            >
              {{ t('triage.approvals.decidedBy', { who: e.decided_by, date: fmt.date(e.decided_at) }) }}<span v-if="e.decision_reason"> : {{ e.decision_reason }}</span>
            </p>
          </div>
          <UButton
            v-if="canEdit && !e.revoked_at && e.status !== 'refused' && !e.expired"
            color="error"
            variant="ghost"
            icon="i-lucide-ban"
            :label="e.status === 'requested' ? t('triage.approvals.withdraw') : t('findings.exceptions.revoke')"
            @click="askRevoke(e)"
          />
        </li>
      </ul>
    </UCard>

    <UModal
      v-model:open="createOpen"
      :title="t('triage.approvals.request')"
      :dismissible="!saving"
    >
      <template #body>
        <div class="space-y-4">
          <p class="text-xs text-muted">
            {{ t('triage.approvals.requestHelp') }}
          </p>
          <UFormField :label="t('findings.exceptions.kind')">
            <USelect
              :model-value="form.kind"
              :items="kindItems"
              class="w-60"
              @update:model-value="changeKind"
            />
          </UFormField>
          <UFormField
            v-for="f in FIELDS[form.kind]"
            :key="`${form.kind}-${f.key}`"
            :label="t(`findings.exceptions.fields.${f.label}`)"
          >
            <UInput
              v-model="form.target[f.key]"
              class="w-full font-mono"
              :data-testid="`target-${f.key}`"
            />
          </UFormField>
          <AiExceptionDraft
            v-if="draftFinding"
            :finding-id="draftFinding"
            @use="useDraft"
          />
          <UFormField :label="t('findings.modal.reason')">
            <UTextarea
              v-model="form.reason"
              :maxlength="2000"
              class="w-full"
              data-testid="exception-reason"
            />
          </UFormField>
          <UFormField
            v-if="vexAllowed"
            :label="t('vex.statusLabel')"
            :help="t('vex.statusHelp')"
          >
            <USelect
              v-model="form.vex_status"
              :items="vexItems"
              class="w-60"
              data-testid="exception-vex-status"
            />
          </UFormField>
          <UFormField
            :label="t('findings.modal.until')"
            :help="t('findings.exceptions.defaultExpiry')"
          >
            <UInput
              v-model="form.expires_on"
              type="date"
              data-testid="exception-until"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="saving"
            :label="t('common.cancel')"
            @click="createOpen = false"
          />
          <UButton
            :loading="saving"
            :disabled="!createValid"
            :label="t('triage.approvals.submit')"
            data-testid="exception-submit"
            @click="create"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="revokeOpen"
      :title="t('findings.exceptions.revokeTitle')"
      :body="t('findings.exceptions.revokeBody')"
      color="error"
      :loading="revoking"
      @confirm="revoke"
    />
  </PageShell>
</template>
