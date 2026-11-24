<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Hors ligne (0.6, chantier A, CLAUDE.md § 9) : clé de l'appliance, clés de
confiance, export et import de lots signés, export périodique, appliance
miroir (F17) et sources de Dependency-Track. Chaque action passe par une
demande au service root, avec indicateur d'attente, puis l'état est relu sans
recharger la page. Toutes les confirmations sont des modales de la console.
-->

<script setup lang="ts">
import { KEY_FINGERPRINT_RE, MIRROR_URL_RE, PUBLIC_KEY_B64_RE } from '#shared/schemas'

const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()
const isAdmin = computed(() => session.can('admin'))

useHead({ title: computed(() => t('offline.title')) })

interface TrustedKey {
  id: string
  label: string
  public_key: string
  fingerprint: string
  added_at: string
  added_by_username: string | null
  revoked_at: string | null
  in_store: boolean
}
interface ExportedBundle {
  name: string
  created_at: string
  size_bytes: number
  sha256: string
  signer_fingerprint: string
  modules: string[]
  feeds?: { id: string, updated_at: string }[]
  images?: string[]
  catalog_version?: number | null
  scheduled?: boolean | null
}
interface HistoryRow {
  id: string
  direction: 'export' | 'import'
  status: string
  contents: Record<string, unknown>
  size_bytes: string | null
  signer_fingerprint: string | null
  error: { code?: string, message?: string } | null
  requested_by_username: string | null
  created_at: string
  finished_at: string | null
}
interface Schedule { enabled: boolean, every_days: number, keep: number, modules: string[], last_run_at: string | null }
interface OfflineView {
  available: boolean
  appliance_key: { public_key: string, fingerprint: string } | null
  trusted_keys: TrustedKey[]
  exports: ExportedBundle[]
  history: HistoryRow[]
  last_import: { at: string, signer_fingerprint: string, created_at: string, catalog_version: number, feeds: string[], images: string[] } | null
  mirror: {
    url: string
    addresses: string[]
    fingerprint: string
    pinned_at: string
    ca: boolean
    last_check: { checked_at: string, error: string | null, manifest: { created_at: string, catalog_version: number, feeds: { id: string, updated_at: string }[], images: string[] } | null } | null
  } | null
  publication: { url: string | null, created_at?: string | null, catalog_version?: number | null, feeds: string[], images: string[] } | null
  schedule: Schedule
  dtrack: {
    configured_at?: string | null
    configure_error?: string | null
    sources: { id: string, available: boolean, ecosystems: string[], updated_at: string | null, reason: string | null }[]
    gaps: { id: string, reason: string }[]
  } | null
}

const EMPTY: OfflineView = {
  available: false, appliance_key: null, trusted_keys: [], exports: [], history: [], last_import: null,
  mirror: null, publication: null, schedule: { enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null }, dtrack: null,
}
const view = ref<OfflineView>(EMPTY)
const loaded = ref(false)
const loadError = ref('')
async function load() {
  try {
    view.value = await api<OfflineView>('/api/system/offline')
    loaded.value = true
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
}
onMounted(load)

/** Modules installés (hors feeds : ils suivent les modules qui les demandent, G1). */
const installed = ref<{ label: string, value: string }[]>([])
onMounted(async () => {
  try {
    const cat = await api<{ modules: { id: string, name: string, type: string, installed: unknown }[] }>('/api/catalog')
    installed.value = cat.modules.filter(m => m.installed && m.type !== 'feed').map(m => ({ label: m.name, value: m.id }))
  }
  catch {
    installed.value = []
  }
})

function size(bytes: number | string | null | undefined): string {
  const n = typeof bytes === 'string' ? Number(bytes) : bytes
  if (typeof n !== 'number' || !Number.isFinite(n)) return '?'
  if (n >= 1024 ** 3) return t('offline.size.gb', { n: (n / 1024 ** 3).toFixed(1) })
  return t('offline.size.mb', { n: Math.max(1, Math.round(n / 1024 ** 2)) })
}
const codeLabel = (code: string | null | undefined) => (code && te(`codes.${code}`) ? t(`codes.${code}`) : code ?? '')

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ title: t('offline.copied'), color: 'success' })
  }
  catch {
    toast.add({ title: t('errors.generic'), color: 'error' })
  }
}

// --- Clés de confiance ---
const keyReq = useHelperRequest()
const addKeyOpen = ref(false)
const newLabel = ref('')
const newKey = ref('')
const newFingerprint = ref<string | null>(null)
const fingerprintAck = ref(false)
watch(newKey, async (value) => {
  newFingerprint.value = null
  fingerprintAck.value = false
  const k = value.trim()
  if (!PUBLIC_KEY_B64_RE.test(k)) return
  try {
    const raw = Uint8Array.from(atob(k), c => c.charCodeAt(0))
    if (raw.length !== 32) return
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw))
    newFingerprint.value = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')
  }
  catch {
    newFingerprint.value = null
  }
})
function openAddKey() {
  newLabel.value = ''
  newKey.value = ''
  newFingerprint.value = null
  fingerprintAck.value = false
  addKeyOpen.value = true
}
async function addKey() {
  if (!newFingerprint.value) return
  const r = await keyReq.run('/api/system/offline/keys', { label: newLabel.value.trim(), public_key: newKey.value.trim(), fingerprint: newFingerprint.value })
  addKeyOpen.value = false
  if (r) await load()
}
const removeKey = ref<TrustedKey | null>(null)
const removeOpen = ref(false)
const removeReq = useHelperRequest()
function askRemove(k: TrustedKey) {
  removeKey.value = k
  removeOpen.value = true
}
async function doRemoveKey() {
  const k = removeKey.value
  if (!k) return
  removeOpen.value = false
  const r = await removeReq.run('/api/system/offline/keys/remove', { fingerprint: k.fingerprint })
  if (r) await load()
}
const activeKeys = computed(() => view.value.trusted_keys.filter(k => !k.revoked_at))

// --- Export ---
const exportModules = ref<string[]>([])
const estimateReq = useHelperRequest()
const exportReq = useHelperRequest()
const estimate = ref<{ estimated_bytes: number, modules: string[], feeds: string[], images: string[] } | null>(null)
watch(exportModules, () => {
  estimate.value = null
})
async function runEstimate() {
  const r = await estimateReq.run('/api/system/offline/export', { modules: exportModules.value, dry_run: true }, { timeoutMs: 10 * 60_000 })
  estimate.value = r?.status === 'ok' ? r.output as typeof estimate.value : null
}
const exportOpen = ref(false)
async function runExport() {
  exportOpen.value = false
  const r = await exportReq.run('/api/system/offline/export', { modules: exportModules.value }, { timeoutMs: 60 * 60_000 })
  if (r) await load()
}

// --- Export périodique ---
const schedule = ref<Schedule>({ enabled: false, every_days: 7, keep: 2, modules: [], last_run_at: null })
const scheduleTouched = ref(false)
watch(view, (v) => {
  if (loaded.value && !scheduleTouched.value) schedule.value = { ...v.schedule, modules: [...v.schedule.modules] }
})
watch(schedule, () => {
  scheduleTouched.value = true
}, { deep: true, flush: 'sync' })
const scheduleReq = useHelperRequest()
const scheduleValid = computed(() => !schedule.value.enabled || schedule.value.modules.length > 0)
async function saveSchedule() {
  const { enabled, every_days, keep, modules } = schedule.value
  const r = await scheduleReq.run('/api/system/offline/schedule', { schedule: { enabled, every_days, keep, modules } })
  scheduleTouched.value = false
  if (r) await load()
}

// --- Import ---
const importFile = ref<File | null>(null)
const importOpen = ref(false)
const uploading = ref(false)
const uploadPct = ref(0)
const importReq = useHelperRequest()
function onImportFile(event: Event) {
  importFile.value = (event.target as HTMLInputElement).files?.[0] ?? null
}
function put(url: string, file: File, csrf: string): Promise<void> {
  // XMLHttpRequest pour l'avancement du téléversement (fetch ne l'expose pas).
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', url)
    xhr.setRequestHeader('content-type', 'application/octet-stream')
    xhr.setRequestHeader('x-csrf-token', csrf)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) uploadPct.value = Math.floor((e.loaded / e.total) * 100)
    }
    xhr.onload = () => (xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error(t('offline.import.uploadFailed', { status: xhr.status }))))
    xhr.onerror = () => reject(new Error(t('offline.import.uploadFailed', { status: 0 })))
    xhr.send(file)
  })
}
async function runImport() {
  const file = importFile.value
  if (!file) return
  importOpen.value = false
  uploading.value = true
  uploadPct.value = 0
  try {
    const { upload_id } = await api<{ upload_id: string }>('/api/system/offline/uploads', { method: 'POST' })
    await put(`/api/system/offline/uploads/${upload_id}`, file, session.state.value.csrf ?? '')
    uploading.value = false
    const r = await importReq.run('/api/system/offline/import', { upload_id }, { timeoutMs: 60 * 60_000 })
    if (r) await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    uploading.value = false
  }
}

// --- Appliance miroir (F17) ---
const mirrorUrl = ref('')
const mirrorFingerprint = ref('')
const mirrorCa = ref('')
const mirrorOpen = ref(false)
const mirrorRemoveOpen = ref(false)
const mirrorReq = useHelperRequest()
const mirrorKeyItems = computed(() => activeKeys.value.filter(k => k.in_store).map(k => ({ label: `${k.label} · ${fmt.fingerprint(k.fingerprint).slice(0, 23)}…`, value: k.fingerprint })))
const mirrorValid = computed(() => MIRROR_URL_RE.test(mirrorUrl.value.trim()) && KEY_FINGERPRINT_RE.test(mirrorFingerprint.value)
  && (!mirrorCa.value.trim() || mirrorCa.value.trim().startsWith('-----BEGIN CERTIFICATE-----')))
async function setMirror() {
  mirrorOpen.value = false
  const ca = mirrorCa.value.trim()
  const r = await mirrorReq.run('/api/system/offline/mirror', {
    enabled: true, url: mirrorUrl.value.trim(), fingerprint: mirrorFingerprint.value, ...(ca ? { ca_pem: `${ca}\n` } : {}),
  })
  if (r) await load()
}
async function removeMirror() {
  mirrorRemoveOpen.value = false
  const r = await mirrorReq.run('/api/system/offline/mirror', { enabled: false })
  if (r) await load()
}

const keyBusy = computed(() => keyReq.running.value)
const removeBusy = computed(() => removeReq.running.value)
const fp = (hex: string | null | undefined) => fmt.fingerprint(hex)
const anyRunning = computed(() => keyReq.running.value || removeReq.running.value || estimateReq.running.value
  || exportReq.running.value || scheduleReq.running.value || importReq.running.value || mirrorReq.running.value || uploading.value)
const runningLabel = computed(() => {
  if (uploading.value) return t('offline.import.uploading', { pct: uploadPct.value })
  for (const r of [keyReq, removeReq, estimateReq, exportReq, scheduleReq, importReq, mirrorReq]) if (r.running.value) return r.label.value
  return ''
})
</script>

<template>
  <PageShell :title="t('offline.title')">
    <template #actions>
      <UButton
        color="neutral"
        variant="ghost"
        icon="i-lucide-refresh-cw"
        :label="t('common.refresh')"
        :disabled="anyRunning"
        @click="load"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <UAlert
      v-if="loaded && !view.available"
      color="warning"
      variant="subtle"
      icon="i-lucide-clock"
      :title="t('offline.unavailable')"
    />
    <div
      v-if="anyRunning"
      class="flex items-center gap-2 text-sm text-muted"
      data-testid="offline-running"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ runningLabel || t('app.loading') }}
    </div>
    <p class="text-sm text-muted">
      {{ t('offline.intro') }}
    </p>

    <div
      v-if="!loaded && !loadError"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="loaded">
      <!-- Clé de l'appliance -->
      <UCard data-testid="offline-appliance-key">
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.key.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.key.help') }}
          </p>
        </template>
        <div
          v-if="view.appliance_key"
          class="space-y-2 text-sm"
        >
          <p>
            {{ t('offline.key.fingerprint') }} :
            <code
              class="break-all"
              data-testid="appliance-fingerprint"
            >{{ fmt.fingerprint(view.appliance_key.fingerprint) }}</code>
          </p>
          <div class="flex flex-wrap items-center gap-2">
            <span>{{ t('offline.key.public') }} :</span>
            <code class="break-all">{{ view.appliance_key.public_key }}</code>
            <UButton
              size="xs"
              variant="ghost"
              icon="i-lucide-copy"
              :label="t('offline.copy')"
              @click="copy(view.appliance_key.public_key)"
            />
          </div>
        </div>
        <p
          v-else
          class="text-sm text-muted"
        >
          {{ t('offline.key.pending') }}
        </p>
      </UCard>

      <!-- Clés de confiance -->
      <UCard data-testid="offline-trusted-keys">
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 class="font-semibold">
                {{ t('offline.trusted.title') }}
              </h2>
              <p class="text-sm text-muted">
                {{ t('offline.trusted.help') }}
              </p>
            </div>
            <UButton
              v-if="isAdmin"
              size="sm"
              variant="soft"
              icon="i-lucide-key-round"
              :label="t('offline.trusted.add')"
              :disabled="anyRunning"
              data-testid="trusted-add"
              @click="openAddKey"
            />
          </div>
        </template>
        <p
          v-if="!view.trusted_keys.length"
          class="text-sm text-muted"
        >
          {{ t('offline.trusted.none') }}
        </p>
        <ul
          v-else
          class="divide-y divide-default text-sm"
        >
          <li
            v-for="k in view.trusted_keys"
            :key="k.id"
            class="flex flex-wrap items-center justify-between gap-2 py-2"
            :data-testid="`trusted-${k.fingerprint}`"
          >
            <div class="min-w-0">
              <p class="font-medium">
                {{ k.label }}
                <UBadge
                  class="ml-2"
                  size="sm"
                  variant="subtle"
                  :color="k.revoked_at ? 'neutral' : k.in_store ? 'success' : 'warning'"
                  :label="k.revoked_at ? t('offline.trusted.revoked') : k.in_store ? t('offline.trusted.active') : t('offline.trusted.notInStore')"
                />
              </p>
              <p class="break-all text-xs text-muted">
                <code>{{ fmt.fingerprint(k.fingerprint) }}</code>
              </p>
              <p class="text-xs text-muted">
                {{ t('offline.trusted.added', { date: fmt.date(k.added_at), user: k.added_by_username ?? t('common.unknown') }) }}
                <template v-if="k.revoked_at">
                  · {{ t('offline.trusted.revokedAt', { date: fmt.date(k.revoked_at) }) }}
                </template>
              </p>
            </div>
            <UButton
              v-if="isAdmin && !k.revoked_at"
              size="xs"
              color="error"
              variant="ghost"
              icon="i-lucide-trash"
              :label="t('offline.trusted.remove')"
              :disabled="anyRunning"
              @click="askRemove(k)"
            />
          </li>
        </ul>
      </UCard>

      <!-- Export -->
      <UCard
        v-if="isAdmin"
        data-testid="offline-export"
      >
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.export.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.export.help') }}
          </p>
        </template>
        <div class="space-y-3">
          <UFormField :label="t('offline.export.modules')">
            <USelectMenu
              v-model="exportModules"
              :items="installed"
              value-key="value"
              multiple
              class="w-full max-w-xl"
              :placeholder="t('offline.export.choose')"
              data-testid="export-modules"
            />
          </UFormField>
          <p
            v-if="estimate"
            class="text-sm"
            data-testid="export-estimate"
          >
            {{ t('offline.export.estimate', { size: size(estimate.estimated_bytes), feeds: estimate.feeds.join(', ') || t('common.none') }) }}
          </p>
          <div class="flex flex-wrap gap-2">
            <UButton
              variant="soft"
              icon="i-lucide-calculator"
              :label="t('offline.export.estimateButton')"
              :loading="estimateReq.running.value"
              :disabled="!exportModules.length || anyRunning"
              @click="runEstimate"
            />
            <UButton
              icon="i-lucide-package"
              :label="t('offline.export.run')"
              :loading="exportReq.running.value"
              :disabled="!exportModules.length || anyRunning"
              data-testid="export-run"
              @click="exportOpen = true"
            />
          </div>
        </div>
        <div class="mt-4">
          <h3 class="text-sm font-semibold">
            {{ t('offline.export.list') }}
          </h3>
          <p
            v-if="!view.exports.length"
            class="text-sm text-muted"
          >
            {{ t('offline.export.none') }}
          </p>
          <ul
            v-else
            class="divide-y divide-default text-sm"
          >
            <li
              v-for="b in view.exports"
              :key="b.name"
              class="flex flex-wrap items-center justify-between gap-2 py-2"
            >
              <div class="min-w-0">
                <p class="font-medium">
                  {{ b.name }}
                  <UBadge
                    v-if="b.scheduled"
                    class="ml-1"
                    size="sm"
                    color="info"
                    variant="subtle"
                    :label="t('offline.export.scheduled')"
                  />
                </p>
                <p class="text-xs text-muted">
                  {{ t('offline.export.line', { date: fmt.date(b.created_at), size: size(b.size_bytes), modules: b.modules.join(', ') }) }}
                </p>
                <p class="break-all text-xs text-muted">
                  SHA-256 <code>{{ b.sha256 }}</code>
                </p>
              </div>
              <UButton
                size="xs"
                variant="soft"
                icon="i-lucide-download"
                :label="t('offline.export.download')"
                :to="`/api/system/offline/bundles/${b.name}`"
                external
                download
              />
            </li>
          </ul>
        </div>
      </UCard>

      <!-- Export périodique -->
      <UCard
        v-if="isAdmin"
        data-testid="offline-schedule"
      >
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.schedule.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.schedule.help') }}
          </p>
        </template>
        <div class="grid gap-4 md:grid-cols-2">
          <UFormField :label="t('offline.schedule.enabled')">
            <USwitch v-model="schedule.enabled" />
          </UFormField>
          <UFormField :label="t('offline.export.modules')">
            <USelectMenu
              v-model="schedule.modules"
              :items="installed"
              value-key="value"
              multiple
              class="w-full"
              :placeholder="t('offline.export.choose')"
            />
          </UFormField>
          <UFormField :label="t('offline.schedule.everyDays')">
            <UInputNumber
              v-model="schedule.every_days"
              :min="1"
              :max="31"
            />
          </UFormField>
          <UFormField :label="t('offline.schedule.keep')">
            <UInputNumber
              v-model="schedule.keep"
              :min="1"
              :max="10"
            />
          </UFormField>
        </div>
        <p class="mt-2 text-xs text-muted">
          {{ schedule.last_run_at ? t('offline.schedule.lastRun', { date: fmt.date(schedule.last_run_at) }) : t('offline.schedule.never') }}
        </p>
        <p
          v-if="!scheduleValid"
          class="mt-1 text-sm text-warning"
        >
          {{ t('offline.schedule.needModules') }}
        </p>
        <template #footer>
          <div class="flex justify-end">
            <UButton
              :label="t('common.save')"
              :loading="scheduleReq.running.value"
              :disabled="!scheduleTouched || !scheduleValid || anyRunning"
              @click="saveSchedule"
            />
          </div>
        </template>
      </UCard>

      <!-- Import -->
      <UCard
        v-if="isAdmin"
        data-testid="offline-import"
      >
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.import.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.import.help') }}
          </p>
        </template>
        <div class="flex flex-wrap items-center gap-3">
          <input
            type="file"
            accept=".tar,application/x-tar"
            class="text-sm"
            data-testid="import-file"
            :disabled="anyRunning"
            @change="onImportFile"
          >
          <UButton
            icon="i-lucide-upload"
            :label="t('offline.import.run')"
            :loading="uploading || importReq.running.value"
            :disabled="!importFile || anyRunning || !activeKeys.length"
            data-testid="import-run"
            @click="importOpen = true"
          />
        </div>
        <p
          v-if="!activeKeys.length"
          class="mt-2 text-sm text-warning"
        >
          {{ t('offline.import.needKey') }}
        </p>
        <UProgress
          v-if="uploading"
          v-model="uploadPct"
          class="mt-3"
        />
        <p
          v-if="view.last_import"
          class="mt-3 text-sm"
          data-testid="last-import"
        >
          {{ t('offline.import.last', {
            date: fmt.date(view.last_import.at),
            created: fmt.date(view.last_import.created_at),
            feeds: view.last_import.feeds.join(', ') || t('common.none'),
            images: view.last_import.images.join(', ') || t('common.none'),
          }) }}
        </p>
      </UCard>

      <!-- Appliance miroir -->
      <UCard data-testid="offline-mirror">
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.mirror.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.mirror.help') }}
          </p>
        </template>
        <div class="space-y-4">
          <div class="text-sm">
            <h3 class="font-semibold">
              {{ t('offline.mirror.publishTitle') }}
            </h3>
            <p
              v-if="view.publication"
              data-testid="mirror-publication"
            >
              {{ t('offline.mirror.published', { url: view.publication.url ?? '?', date: fmt.date(view.publication.created_at ?? null) }) }}
            </p>
            <p
              v-else
              class="text-muted"
            >
              {{ t('offline.mirror.notPublished') }}
            </p>
          </div>
          <div class="text-sm">
            <h3 class="font-semibold">
              {{ t('offline.mirror.clientTitle') }}
            </h3>
            <template v-if="view.mirror">
              <p data-testid="mirror-declared">
                {{ t('offline.mirror.declared', { url: view.mirror.url, addresses: view.mirror.addresses.join(', ') }) }}
              </p>
              <p class="break-all text-xs text-muted">
                {{ t('offline.key.fingerprint') }} : <code>{{ fmt.fingerprint(view.mirror.fingerprint) }}</code>
              </p>
              <p
                v-if="view.mirror.last_check?.error"
                class="text-warning"
              >
                {{ t('offline.mirror.lastError', { date: fmt.date(view.mirror.last_check.checked_at), error: view.mirror.last_check.error }) }}
              </p>
              <p
                v-else-if="view.mirror.last_check?.manifest"
                class="text-muted"
              >
                {{ t('offline.mirror.lastOk', { date: fmt.date(view.mirror.last_check.checked_at), created: fmt.date(view.mirror.last_check.manifest.created_at) }) }}
              </p>
              <UButton
                v-if="isAdmin"
                class="mt-2"
                size="sm"
                color="error"
                variant="soft"
                icon="i-lucide-unplug"
                :label="t('offline.mirror.remove')"
                :disabled="anyRunning"
                @click="mirrorRemoveOpen = true"
              />
            </template>
            <div
              v-else-if="isAdmin"
              class="mt-2 grid gap-3 md:grid-cols-2"
            >
              <UFormField :label="t('offline.mirror.url')">
                <UInput
                  v-model="mirrorUrl"
                  placeholder="https://mirror.analyse.exemple.test"
                  class="w-full"
                  data-testid="mirror-url"
                />
              </UFormField>
              <UFormField
                :label="t('offline.mirror.key')"
                :help="mirrorKeyItems.length ? undefined : t('offline.mirror.needKey')"
              >
                <USelect
                  v-model="mirrorFingerprint"
                  :items="mirrorKeyItems"
                  class="w-full"
                  :placeholder="t('offline.mirror.chooseKey')"
                />
              </UFormField>
              <UFormField
                class="md:col-span-2"
                :label="t('offline.mirror.ca')"
                :help="t('offline.mirror.caHelp')"
              >
                <UTextarea
                  v-model="mirrorCa"
                  :rows="3"
                  class="w-full font-mono text-xs"
                />
              </UFormField>
              <div class="md:col-span-2">
                <UButton
                  icon="i-lucide-plug"
                  :label="t('offline.mirror.set')"
                  :disabled="!mirrorValid || anyRunning"
                  data-testid="mirror-set"
                  @click="mirrorOpen = true"
                />
              </div>
            </div>
            <p
              v-else
              class="text-muted"
            >
              {{ t('offline.mirror.none') }}
            </p>
          </div>
        </div>
      </UCard>

      <!-- Dependency-Track -->
      <UCard
        v-if="view.dtrack"
        data-testid="offline-dtrack"
      >
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.dtrack.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('offline.dtrack.help') }}
          </p>
        </template>
        <ul class="space-y-1 text-sm">
          <li
            v-for="s in view.dtrack.sources"
            :key="s.id"
          >
            <UIcon
              :name="s.available ? 'i-lucide-circle-check' : 'i-lucide-circle-alert'"
              :class="s.available ? 'text-success' : 'text-warning'"
              class="align-middle"
            />
            {{ te(`offline.dtrack.sources.${s.id}`) ? t(`offline.dtrack.sources.${s.id}`) : s.id }} :
            {{ s.available ? t('offline.dtrack.served', { date: fmt.date(s.updated_at), ecosystems: s.ecosystems.length }) : t('offline.dtrack.missing') }}
          </li>
        </ul>
        <h3 class="mt-3 text-sm font-semibold">
          {{ t('offline.dtrack.gapsTitle') }}
        </h3>
        <ul
          class="space-y-1 text-sm text-muted"
          data-testid="dtrack-gaps"
        >
          <li
            v-for="g in view.dtrack.gaps"
            :key="g.id"
          >
            {{ te(`offline.dtrack.gaps.${g.id}`) ? t(`offline.dtrack.gaps.${g.id}`) : g.id }}
          </li>
        </ul>
        <p
          v-if="view.dtrack.configure_error"
          class="mt-2 text-sm text-warning"
        >
          {{ t('offline.dtrack.configureError', { error: view.dtrack.configure_error }) }}
        </p>
      </UCard>

      <!-- Historique -->
      <UCard v-if="view.history.length">
        <template #header>
          <h2 class="font-semibold">
            {{ t('offline.history.title') }}
          </h2>
        </template>
        <ul class="divide-y divide-default text-sm">
          <li
            v-for="h in view.history"
            :key="h.id"
            class="py-2"
          >
            <span class="font-medium">{{ t(`offline.history.${h.direction}`) }}</span>
            · {{ fmt.date(h.created_at) }}
            · {{ te(`offline.history.status.${h.status}`) ? t(`offline.history.status.${h.status}`) : h.status }}
            <template v-if="h.size_bytes">
              · {{ size(h.size_bytes) }}
            </template>
            <template v-if="h.requested_by_username">
              · {{ h.requested_by_username }}
            </template>
            <p
              v-if="h.error"
              class="text-xs text-warning"
            >
              {{ codeLabel(h.error.code) || h.error.message }}
            </p>
          </li>
        </ul>
      </UCard>
    </template>

    <!-- Modales -->
    <UModal
      v-model:open="addKeyOpen"
      :title="t('offline.trusted.addTitle')"
      :dismissible="!keyBusy"
    >
      <template #body>
        <div class="space-y-3">
          <p class="text-sm text-muted">
            {{ t('offline.trusted.addHelp') }}
          </p>
          <UFormField :label="t('offline.trusted.label')">
            <UInput
              v-model="newLabel"
              class="w-full"
              :placeholder="t('offline.trusted.labelPlaceholder')"
              data-testid="trusted-label"
            />
          </UFormField>
          <UFormField :label="t('offline.key.public')">
            <UInput
              v-model="newKey"
              class="w-full font-mono"
              data-testid="trusted-key"
            />
          </UFormField>
          <div
            v-if="newFingerprint"
            class="space-y-2 rounded-md border border-default p-3 text-sm"
          >
            <p>{{ t('offline.trusted.checkFingerprint') }}</p>
            <code
              class="block break-all"
              data-testid="trusted-fingerprint"
            >{{ fp(newFingerprint) }}</code>
            <UCheckbox
              v-model="fingerprintAck"
              :label="t('offline.trusted.ack')"
              data-testid="trusted-ack"
            />
          </div>
          <p
            v-else-if="newKey.trim()"
            class="text-sm text-warning"
          >
            {{ t('offline.trusted.invalid') }}
          </p>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :label="t('common.cancel')"
            :disabled="keyBusy"
            @click="addKeyOpen = false"
          />
          <UButton
            :label="t('offline.trusted.add')"
            :loading="keyBusy"
            :disabled="!newFingerprint || !fingerprintAck || !newLabel.trim()"
            data-testid="trusted-confirm"
            @click="addKey"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="removeOpen"
      :title="t('offline.trusted.removeTitle')"
      :body="t('offline.trusted.removeBody', { label: removeKey?.label ?? '', fingerprint: fp(removeKey?.fingerprint) })"
      :ack="t('offline.trusted.removeAck')"
      color="error"
      :confirm-label="t('offline.trusted.remove')"
      :loading="removeBusy"
      @confirm="doRemoveKey"
    />

    <ConfirmModal
      v-model:open="exportOpen"
      :title="t('offline.export.confirmTitle')"
      :body="t('offline.export.confirmBody', { modules: exportModules.join(', '), size: estimate ? size(estimate.estimated_bytes) : '?' })"
      :confirm-label="t('offline.export.run')"
      @confirm="runExport"
    />

    <ConfirmModal
      v-model:open="importOpen"
      :title="t('offline.import.confirmTitle')"
      :body="t('offline.import.confirmBody', { name: importFile?.name ?? '', size: size(importFile?.size ?? null) })"
      :confirm-label="t('offline.import.run')"
      @confirm="runImport"
    />

    <ConfirmModal
      v-model:open="mirrorOpen"
      :title="t('offline.mirror.confirmTitle')"
      :body="t('offline.mirror.confirmBody', { url: mirrorUrl.trim(), fingerprint: fp(mirrorFingerprint) })"
      :ack="t('offline.mirror.confirmAck')"
      color="warning"
      :confirm-label="t('offline.mirror.set')"
      @confirm="setMirror"
    />

    <ConfirmModal
      v-model:open="mirrorRemoveOpen"
      :title="t('offline.mirror.removeTitle')"
      :body="t('offline.mirror.removeBody')"
      color="error"
      :confirm-label="t('offline.mirror.remove')"
      @confirm="removeMirror"
    />
  </PageShell>
</template>
