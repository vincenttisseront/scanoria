<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Mises à jour : version installée et disponible, notes de version, canal,
installation immédiate ou planifiée, retour à N-1, import hors ligne.
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { ARCHIVE_NAME_RE, UPLOAD_FILE_NAMES, WEEK_DAYS, requestParamSchemas } from '#shared/schemas'

type WeekDay = (typeof WEEK_DAYS)[number]

const { t, te } = useI18n()
useHead({ title: computed(() => t('updates.title')) })

const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const { api, errorMessage } = useApi()
const toast = useToast()
const { data, state, failed, refresh } = useApplianceState(15_000)

// --- Historique ---
interface HistoryRow {
  id: string
  action: 'apply' | 'rollback' | 'auto-rollback'
  from_version: string
  to_version: string
  status: 'success' | 'failed' | 'rolled-back'
  code: string | null
  initiated_by: string | null
  started_at: string
}
const history = ref<HistoryRow[]>([])
async function loadHistory() {
  try {
    history.value = (await api<{ items: HistoryRow[] }>('/api/system/updates/history')).items
  }
  catch {
    history.value = []
  }
}
onMounted(loadHistory)
const historyColumns = computed<TableColumn<HistoryRow>[]>(() => [
  { accessorKey: 'started_at', header: t('updates.history.date'), cell: ({ row }) => fmt.date(row.original.started_at) },
  { accessorKey: 'action', header: t('updates.history.action'), cell: ({ row }) => t(`updates.history.actions.${row.original.action}`) },
  { id: 'versions', header: t('updates.history.versions'), cell: ({ row }) => `${row.original.from_version} → ${row.original.to_version}` },
  {
    accessorKey: 'status',
    header: t('updates.history.status'),
    cell: ({ row }) => `${t(`updates.history.statuses.${row.original.status}`)}${row.original.code && row.original.code !== 'OK' ? ` (${row.original.code})` : ''}`,
  },
  { accessorKey: 'initiated_by', header: t('updates.history.by'), cell: ({ row }) => row.original.initiated_by ?? 'system' },
])

// --- Recherche ---
const checkReq = useHelperRequest()
async function checkNow() {
  await checkReq.run('/api/system/updates/check', {})
  await refresh()
}

// --- Installation ---
const installModal = ref(false)
const installReq = useHelperRequest()
async function installNow() {
  const version = state.value?.update.latest_version
  if (!version) return
  const r = await installReq.run('/api/system/updates/apply', { source: 'github', version })
  installModal.value = false
  await afterLongRequest(r)
}

async function afterLongRequest(r: { status: string } | null) {
  await refresh()
  await loadHistory()
  if (r?.status === 'ok') {
    // nouvelle version de la console : recharger l'application
    setTimeout(() => window.location.reload(), 1500)
  }
}

// --- Retour à N-1 ---
const rollbackModal = ref(false)
const rollbackReq = useHelperRequest()
async function rollback() {
  const s = state.value
  if (!s?.appliance.previous_version) return
  const r = await rollbackReq.run('/api/system/updates/rollback', {
    expected_current: s.appliance.version,
    expected_target: s.appliance.previous_version,
  })
  rollbackModal.value = false
  await afterLongRequest(r)
}

// --- Politique ---
const policy = reactive({
  channel: 'stable' as 'stable' | 'prerelease',
  auto_check: true,
  auto_apply: false,
  days: ['sun'] as WeekDay[],
  start: '03:00',
  duration_minutes: 120,
})
const policyLoaded = ref(false)
watch(state, (s) => {
  if (!s || policyLoaded.value) return
  policyLoaded.value = true
  policy.channel = s.update.channel
  policy.auto_check = s.update.auto_check
  policy.auto_apply = s.update.auto_apply
  if (s.update.maintenance_window) {
    policy.days = WEEK_DAYS.filter(d => s.update.maintenance_window!.days.includes(d))
    policy.start = s.update.maintenance_window.start
    policy.duration_minutes = s.update.maintenance_window.duration_minutes
  }
}, { immediate: true })
const useWindow = ref(false)
watch(() => policy.auto_apply, (v) => {
  if (v) useWindow.value = true
})
watch(state, (s) => {
  if (s?.update.maintenance_window) useWindow.value = true
}, { immediate: true })
const policyParams = computed(() => ({
  channel: policy.channel,
  auto_check: policy.auto_check,
  auto_apply: policy.auto_apply,
  maintenance_window: useWindow.value || policy.auto_apply
    ? { days: WEEK_DAYS.filter(d => policy.days.includes(d)), start: policy.start, duration_minutes: Number(policy.duration_minutes) }
    : null,
}))
const policyValid = computed(() => requestParamSchemas['set-update-policy'].safeParse(policyParams.value).success)
const policyReq = useHelperRequest()
async function savePolicy() {
  await policyReq.run('/api/system/updates/policy', policyParams.value)
  await refresh()
}
const channelItems = computed(() => [
  { label: t('updates.channels.stable'), value: 'stable' },
  { label: t('updates.channels.prerelease'), value: 'prerelease' },
])
const dayItems = computed(() => WEEK_DAYS.map(d => ({ label: t(`updates.days.${d}`), value: d })))

// --- Import hors ligne ---
const uploadFiles = ref<File[]>([])
const uploading = ref('')
const uploadReq = useHelperRequest()
const uploadModal = ref(false)
function onFiles(event: Event) {
  const input = event.target as HTMLInputElement
  uploadFiles.value = Array.from(input.files ?? [])
}
const archiveFile = computed(() => uploadFiles.value.find(f => ARCHIVE_NAME_RE.test(f.name)))
const missingFiles = computed(() => {
  const names = new Set(uploadFiles.value.map(f => f.name))
  const missing: string[] = UPLOAD_FILE_NAMES.filter(n => !names.has(n))
  if (!archiveFile.value) missing.unshift('scanoria-X.Y.Z.tar.zst')
  return missing
})
async function uploadAndInstall() {
  const csrf = session.state.value.csrf ?? ''
  try {
    const { upload_id } = await api<{ upload_id: string }>('/api/system/updates/uploads', { method: 'POST' })
    const wanted = [...UPLOAD_FILE_NAMES, archiveFile.value!.name]
    for (const name of wanted) {
      const file = uploadFiles.value.find(f => f.name === name)!
      uploading.value = name
      await $fetch(`/api/system/updates/uploads/${upload_id}/${encodeURIComponent(name)}`, {
        method: 'PUT',
        body: file,
        headers: { 'x-csrf-token': csrf, 'content-type': 'application/octet-stream' },
      })
    }
    uploading.value = ''
    const r = await uploadReq.run('/api/system/updates/apply', { source: 'upload', upload_id })
    uploadModal.value = false
    await afterLongRequest(r)
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    uploading.value = ''
    uploadModal.value = false
  }
}

const anyRunning = computed(() =>
  checkReq.running.value || installReq.running.value || rollbackReq.running.value
  || policyReq.running.value || uploadReq.running.value || !!uploading.value,
)
const codeLabel = (code: string | null | undefined) => (code && te(`codes.${code}`) ? t(`codes.${code}`) : code ?? '')
</script>

<template>
  <PageShell :title="t('updates.title')">
    <StateAlert
      :data="data"
      :failed="failed"
    />

    <div
      v-if="state"
      class="grid gap-4 md:grid-cols-2"
    >
      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('updates.installed') }}
          </h2>
        </template>
        <p class="text-2xl font-semibold">
          {{ state.appliance.version }}
        </p>
        <p class="mt-1 text-sm text-muted">
          {{ t('updates.previous') }} : {{ state.appliance.previous_version ?? t('common.none') }}
        </p>
        <p class="mt-1 text-sm text-muted">
          {{ t('updates.channel') }} : {{ t(`updates.channels.${state.update.channel}`) }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('updates.available') }}
          </h2>
        </template>
        <p
          v-if="state.update.available && state.update.latest_version"
          class="text-2xl font-semibold text-info"
        >
          {{ state.update.latest_version }}
        </p>
        <p
          v-else
          class="text-sm"
        >
          {{ t('updates.noneAvailable') }}
        </p>
        <p class="mt-1 text-sm text-muted">
          {{ state.update.last_check_at ? t('updates.lastCheck', { date: fmt.date(state.update.last_check_at) }) : t('updates.neverChecked') }}
          <template v-if="state.update.last_check_code && state.update.last_check_code !== 'OK'">
            · {{ t('updates.lastCheckCode', { code: codeLabel(state.update.last_check_code) }) }}
          </template>
        </p>
        <p
          v-if="state.update.published_at"
          class="text-sm text-muted"
        >
          {{ t('updates.publishedAt', { date: fmt.date(state.update.published_at) }) }}
        </p>
        <p
          v-if="state.update.skipped_version"
          class="text-sm text-muted"
        >
          {{ t('updates.skippedVersion', { version: state.update.skipped_version }) }}
        </p>
        <div
          v-if="isAdmin"
          class="mt-4 flex flex-wrap items-center gap-3"
        >
          <UButton
            icon="i-lucide-search"
            color="neutral"
            variant="outline"
            :loading="checkReq.running.value"
            :disabled="anyRunning && !checkReq.running.value"
            :label="t('updates.check')"
            @click="checkNow"
          />
          <UButton
            v-if="state.update.available && state.update.latest_version"
            icon="i-lucide-download"
            :loading="installReq.running.value"
            :disabled="anyRunning && !installReq.running.value"
            :label="t('updates.installNow')"
            @click="installModal = true"
          />
        </div>
        <div class="mt-2 space-y-1">
          <RequestProgress
            :active="checkReq.running.value"
            :label="checkReq.label.value"
          />
          <RequestProgress
            :active="installReq.running.value"
            :label="installReq.label.value"
          />
        </div>
      </UCard>
    </div>

    <UCard v-if="state?.update.notes_md">
      <template #header>
        <h2 class="font-semibold">
          {{ t('updates.notes') }} — {{ state.update.latest_version }}
        </h2>
      </template>
      <pre class="max-h-96 overflow-auto whitespace-pre-wrap font-sans text-sm">{{ state.update.notes_md }}</pre>
    </UCard>

    <UCard v-if="state && isAdmin">
      <template #header>
        <h2 class="font-semibold">
          {{ t('updates.policyTitle') }}
        </h2>
      </template>
      <div class="grid gap-4 md:grid-cols-2">
        <UFormField :label="t('updates.channel')">
          <USelect
            v-model="policy.channel"
            :items="channelItems"
            class="w-full"
          />
        </UFormField>
        <div class="space-y-3 pt-6">
          <USwitch
            v-model="policy.auto_check"
            :label="t('updates.autoCheck')"
          />
          <USwitch
            v-model="policy.auto_apply"
            :label="t('updates.autoApply')"
          />
          <USwitch
            v-model="useWindow"
            :disabled="policy.auto_apply"
            :label="t('updates.window')"
          />
        </div>
        <template v-if="useWindow || policy.auto_apply">
          <UFormField
            :label="t('updates.windowDays')"
            class="md:col-span-2"
          >
            <UCheckboxGroup
              v-model="policy.days"
              :items="dayItems"
              orientation="horizontal"
            />
          </UFormField>
          <UFormField :label="t('updates.windowStart')">
            <UInput
              v-model="policy.start"
              type="time"
              class="w-40"
            />
          </UFormField>
          <UFormField :label="t('updates.windowDuration')">
            <UInputNumber
              v-model="policy.duration_minutes"
              :min="30"
              :max="480"
              :step="30"
              class="w-40"
            />
          </UFormField>
        </template>
      </div>
      <p
        v-if="policy.auto_apply && !policyValid"
        class="mt-2 text-sm text-warning"
      >
        {{ t('updates.windowRequired') }}
      </p>
      <div class="mt-4 flex items-center gap-4">
        <UButton
          icon="i-lucide-calendar-clock"
          :disabled="!policyValid || (anyRunning && !policyReq.running.value)"
          :loading="policyReq.running.value"
          :label="t('updates.savePolicy')"
          @click="savePolicy"
        />
        <RequestProgress
          :active="policyReq.running.value"
          :label="policyReq.label.value"
        />
      </div>
    </UCard>

    <UCard v-if="state && isAdmin">
      <template #header>
        <h2 class="font-semibold">
          {{ t('updates.rollbackTitle') }}
        </h2>
      </template>
      <template v-if="state.appliance.previous_version">
        <p class="text-sm">
          {{ t('updates.rollbackHelp', { version: state.appliance.previous_version }) }}
        </p>
        <div class="mt-4 flex items-center gap-4">
          <UButton
            icon="i-lucide-undo-2"
            color="warning"
            variant="outline"
            :loading="rollbackReq.running.value"
            :disabled="anyRunning && !rollbackReq.running.value"
            :label="t('updates.rollback', { version: state.appliance.previous_version })"
            @click="rollbackModal = true"
          />
          <RequestProgress
            :active="rollbackReq.running.value"
            :label="rollbackReq.label.value"
          />
        </div>
      </template>
      <p
        v-else
        class="text-sm text-muted"
      >
        {{ t('updates.rollbackNone') }}
      </p>
    </UCard>

    <UCard v-if="isAdmin">
      <template #header>
        <h2 class="font-semibold">
          {{ t('updates.uploadTitle') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('updates.uploadHelp') }}
        </p>
      </template>
      <div class="space-y-3">
        <div class="space-y-1">
          <label
            for="update-upload-files"
            class="block text-sm font-medium"
          >{{ t('updates.uploadFiles') }}</label>
          <input
            id="update-upload-files"
            type="file"
            multiple
            accept=".zst,.json,.sig,application/octet-stream"
            class="block text-sm"
            :disabled="anyRunning"
            @change="onFiles"
          >
        </div>
        <p
          v-if="uploadFiles.length && missingFiles.length"
          class="text-sm text-warning"
        >
          {{ t('updates.uploadMissing', { names: missingFiles.join(', ') }) }}
        </p>
        <div class="flex items-center gap-4">
          <UButton
            icon="i-lucide-upload"
            :disabled="!uploadFiles.length || missingFiles.length > 0 || anyRunning"
            :loading="!!uploading || uploadReq.running.value"
            :label="t('updates.uploadSubmit')"
            @click="uploadModal = true"
          />
          <RequestProgress
            :active="!!uploading"
            :label="t('updates.uploading', { name: uploading })"
          />
          <RequestProgress
            :active="uploadReq.running.value"
            :label="uploadReq.label.value"
          />
        </div>
      </div>
    </UCard>

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('updates.historyTitle') }}
        </h2>
      </template>
      <UTable
        :data="history"
        :columns="historyColumns"
        :empty="t('common.none')"
      />
    </UCard>

    <ConfirmModal
      v-model:open="installModal"
      :title="t('updates.installConfirmTitle', { version: state?.update.latest_version ?? '' })"
      :body="t('updates.installConfirmBody')"
      :loading="installReq.running.value"
      @confirm="installNow"
    >
      <RequestProgress
        :active="installReq.running.value"
        :label="installReq.label.value"
      />
    </ConfirmModal>

    <ConfirmModal
      v-model:open="uploadModal"
      :title="t('updates.installConfirmTitle', { version: archiveFile?.name.replace(/^scanoria-|\.tar\.zst$/g, '') ?? '' })"
      :body="t('updates.installConfirmBody')"
      :loading="!!uploading || uploadReq.running.value"
      @confirm="uploadAndInstall"
    >
      <RequestProgress
        :active="!!uploading"
        :label="t('updates.uploading', { name: uploading })"
      />
      <RequestProgress
        :active="uploadReq.running.value"
        :label="uploadReq.label.value"
      />
    </ConfirmModal>

    <ConfirmModal
      v-model:open="rollbackModal"
      :title="t('updates.rollbackConfirmTitle', { version: state?.appliance.previous_version ?? '' })"
      :body="t('updates.rollbackConfirmBody')"
      color="error"
      :ack="t('updates.rollbackAck')"
      :loading="rollbackReq.running.value"
      @confirm="rollback"
    >
      <RequestProgress
        :active="rollbackReq.running.value"
        :label="rollbackReq.label.value"
      />
    </ConfirmModal>
  </PageShell>
</template>
