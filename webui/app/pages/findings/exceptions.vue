<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Exceptions d'un projet (§ 6.1) : motivées et datées, un an au plus, échues
d'elles-mêmes, révocables (modale de la console). Une exception sur un avis
MAL- ou un résultat malveillant est refusée par le serveur (H4).
Lien direct : ?project_id=…&finding_id=… ouvre la création pré-remplie.
-->

<script setup lang="ts">
import { EXCEPTION_KINDS } from '#shared/analysis'

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
  created_by: string | null
  created_at: string
  revoked_at: string | null
  revoked_by: string | null
  active: boolean
  expired: boolean
}

const projects = ref<{ project_id: string, project_name: string }[]>([])
const projectId = ref(typeof route.query.project_id === 'string' ? route.query.project_id : '')
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
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(async () => {
  await loadProjects()
  await load()
  if (typeof route.query.finding_id === 'string' && canEdit.value) openCreate('finding', { finding_id: route.query.finding_id })
})
watch([projectId, showAll], load)

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
function stateOf(e: ExceptionRow): { label: string, color: 'success' | 'neutral' | 'warning' } {
  if (e.revoked_at) return { label: t('findings.exceptions.revoked'), color: 'neutral' }
  if (e.expired) return { label: t('findings.exceptions.expired'), color: 'warning' }
  return { label: t('findings.exceptions.active'), color: 'success' }
}

// --- Création ---
function isoDay(days: number) {
  const d = new Date()
  d.setUTCDate(d.getUTCDate() + days)
  return d.toISOString().slice(0, 10)
}
const createOpen = ref(false)
const saving = ref(false)
const form = reactive<{ kind: Kind, target: Record<string, string>, reason: string, expires_on: string }>({
  kind: 'path', target: {}, reason: '', expires_on: isoDay(90),
})
function openCreate(kind: Kind = 'path', target: Record<string, string> = {}) {
  Object.assign(form, { kind, target: { ...target }, reason: '', expires_on: isoDay(90) })
  createOpen.value = true
}
function changeKind(kind: Kind) {
  form.kind = kind
  form.target = {}
}
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
    await api('/api/exceptions', { method: 'POST', body: { project_id: projectId.value, kind: form.kind, target, reason: form.reason.trim(), expires_on: form.expires_on } })
    toast.add({ title: t('findings.exceptions.created'), color: 'success' })
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
    <template #actions>
      <UButton
        to="/findings"
        icon="i-lucide-list-checks"
        color="neutral"
        variant="ghost"
        :label="t('findings.title')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('findings.exceptions.help') }}
    </p>

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
        :label="t('findings.exceptions.create')"
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
              />
            </div>
            <p class="whitespace-pre-wrap break-words">
              {{ e.reason }}
            </p>
            <p class="text-xs text-muted">
              {{ t('findings.exceptions.expires') }} : {{ e.expires_on }} · {{ t('findings.exceptions.createdBy') }} : {{ e.created_by ?? '—' }}, {{ fmt.date(e.created_at) }}
            </p>
          </div>
          <UButton
            v-if="canEdit && e.active"
            color="error"
            variant="ghost"
            icon="i-lucide-ban"
            :label="t('findings.exceptions.revoke')"
            @click="askRevoke(e)"
          />
        </li>
      </ul>
    </UCard>

    <UModal
      v-model:open="createOpen"
      :title="t('findings.exceptions.create')"
      :dismissible="!saving"
    >
      <template #body>
        <div class="space-y-4">
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
          <UFormField :label="t('findings.modal.reason')">
            <UTextarea
              v-model="form.reason"
              :maxlength="2000"
              class="w-full"
              data-testid="exception-reason"
            />
          </UFormField>
          <UFormField
            :label="t('findings.modal.until')"
            :help="t('findings.exceptions.defaultExpiry')"
          >
            <UInput
              v-model="form.expires_on"
              type="date"
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
            :label="t('common.confirm')"
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
