<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

H7 : VEX d'un projet. Déclarations en vigueur (exceptions approuvées portant
un statut VEX, et déclarations importées gardées pour information), export
OpenVEX 0.2 ou CycloneDX VEX, et import d'un document : aperçu d'abord, puis
confirmation dans une modale de la console. Un import ne crée que des
DEMANDES d'exception (requested_via « tool-import »), jamais une approbation.
-->

<script setup lang="ts">
const props = defineProps<{ projectId: string }>()
const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const session = useSession()
const isOperator = computed(() => session.can('operator'))

interface Statement { vuln_id: string, product: string, status: string, justification: string | null, impact_statement: string | null, timestamp: string }
interface Effect { vuln_id: string, product: string, status: string, action: 'request' | 'store' | 'duplicate' | 'refused', reason?: string }
interface ImportResult { format: string, dry_run: boolean, effects: Effect[], counts: Record<Effect['action'], number> }

const statements = ref<Statement[]>([])
const sha256 = ref('')
const loading = ref(false)
const loadError = ref('')

async function load() {
  loading.value = true
  try {
    const r = await api<{ sha256: string, statements: Statement[] }>(`/api/vex/projects/${props.projectId}/statements`)
    statements.value = r.statements
    sha256.value = r.sha256
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const exportUrl = (format: 'openvex' | 'cyclonedx') => `/api/vex/projects/${props.projectId}/export?format=${format}`
const statusLabel = (s: string) => (te(`vex.status.${s}`) ? t(`vex.status.${s}`) : s)
const justificationLabel = (j: string) => (te(`vex.justification.${j}`) ? t(`vex.justification.${j}`) : j)
const statusColor = (s: string) => (s === 'affected' ? 'error' : s === 'under_investigation' ? 'warning' : s === 'fixed' ? 'success' : 'neutral')

// --- Import : aperçu, puis confirmation ---
const importOpen = ref(false)
const docText = ref('')
const preview = ref<ImportResult | null>(null)
const previewing = ref(false)
const importing = ref(false)
const importError = ref('')

function openImport() {
  docText.value = ''
  preview.value = null
  importError.value = ''
  importOpen.value = true
}
async function onFile(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  if (!file) return
  docText.value = await file.text()
  preview.value = null
}
function importMessage(err: unknown): string {
  const reason = (err as { data?: { data?: { reason?: string } } })?.data?.data?.reason
  return reason && te(`vex.errors.${reason}`) ? t(`vex.errors.${reason}`) : errorMessage(err)
}
async function send(dryRun: boolean) {
  importError.value = ''
  const flag = dryRun ? previewing : importing
  flag.value = true
  try {
    const r = await api<ImportResult>(`/api/vex/projects/${props.projectId}/import`, { method: 'POST', body: { document: docText.value, dry_run: dryRun } })
    if (dryRun) {
      preview.value = r
    }
    else {
      toast.add({ title: t('vex.imported', { n: r.counts.request }), color: 'success' })
      importOpen.value = false
      await load()
    }
  }
  catch (err) {
    importError.value = importMessage(err)
  }
  finally {
    flag.value = false
  }
}
watch(docText, () => {
  preview.value = null
})
</script>

<template>
  <UCard data-testid="vex-panel">
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-2">
        <h2 class="font-semibold">
          {{ t('vex.title') }}
        </h2>
        <div class="flex flex-wrap gap-2">
          <UButton
            :to="exportUrl('openvex')"
            external
            size="sm"
            variant="soft"
            icon="i-lucide-download"
            :label="t('vex.exportOpenVex')"
            data-testid="vex-export-openvex"
          />
          <UButton
            :to="exportUrl('cyclonedx')"
            external
            size="sm"
            variant="soft"
            icon="i-lucide-download"
            :label="t('vex.exportCycloneDx')"
          />
          <UButton
            v-if="isOperator"
            size="sm"
            icon="i-lucide-upload"
            :label="t('vex.import')"
            data-testid="vex-import"
            @click="openImport"
          />
        </div>
      </div>
    </template>
    <p class="mb-3 text-sm text-muted">
      {{ t('vex.help') }}
    </p>
    <div
      v-if="loading && !statements.length"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <UAlert
      v-else-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <p
      v-else-if="!statements.length"
      class="text-sm text-muted"
    >
      {{ t('vex.empty') }}
    </p>
    <ul
      v-else
      class="divide-y divide-default text-sm"
      data-testid="vex-statements"
    >
      <li
        v-for="s in statements"
        :key="`${s.vuln_id}|${s.product}|${s.status}`"
        class="flex flex-wrap items-center gap-2 py-2"
      >
        <code>{{ s.vuln_id }}</code>
        <UBadge
          :color="statusColor(s.status)"
          variant="subtle"
          size="sm"
          :label="statusLabel(s.status)"
        />
        <span
          v-if="s.justification"
          class="text-xs"
        >{{ justificationLabel(s.justification) }}</span>
        <span class="break-all text-xs text-muted">{{ s.product }}</span>
      </li>
    </ul>
    <p
      v-if="sha256"
      class="mt-2 break-all text-xs text-muted"
    >
      SHA-256 : {{ sha256 }}
    </p>

    <UModal
      v-model:open="importOpen"
      :title="t('vex.importTitle')"
      :dismissible="!importing && !previewing"
    >
      <template #body>
        <div class="space-y-3 text-sm">
          <p class="text-muted">
            {{ t('vex.importHelp') }}
          </p>
          <p class="text-xs text-warning">
            {{ t('vex.importScope') }}
          </p>
          <input
            type="file"
            accept=".json,application/json"
            data-testid="vex-file"
            @change="onFile"
          >
          <UTextarea
            v-model="docText"
            :rows="6"
            class="w-full font-mono"
            :placeholder="t('vex.paste')"
          />
          <UAlert
            v-if="importError"
            color="error"
            variant="subtle"
            :title="importError"
          />
          <div
            v-if="preview"
            data-testid="vex-preview"
          >
            <p class="font-medium">
              {{ t('vex.previewTitle', { format: preview.format }) }}
            </p>
            <p>
              {{ t('vex.counts.request', { n: preview.counts.request }) }} ·
              {{ t('vex.counts.store', { n: preview.counts.store }) }} ·
              {{ t('vex.counts.duplicate', { n: preview.counts.duplicate }) }} ·
              {{ t('vex.counts.refused', { n: preview.counts.refused }) }}
            </p>
            <ul class="mt-2 max-h-48 space-y-1 overflow-auto">
              <li
                v-for="(e, i) in preview.effects"
                :key="i"
                class="text-xs"
              >
                <code>{{ e.vuln_id }}</code> · {{ statusLabel(e.status) }} → {{ t(`vex.actions.${e.action}`) }}
                <template v-if="e.reason && te(`vex.refusals.${e.reason}`)">
                  ({{ t(`vex.refusals.${e.reason}`) }})
                </template>
              </li>
            </ul>
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="importing"
            :label="t('common.cancel')"
            @click="importOpen = false"
          />
          <UButton
            variant="soft"
            :loading="previewing"
            :disabled="docText.length < 2"
            :label="t('vex.preview')"
            data-testid="vex-preview-button"
            @click="send(true)"
          />
          <UButton
            :loading="importing"
            :disabled="!preview || !preview.counts.request && !preview.counts.store"
            :label="t('vex.confirmImport')"
            data-testid="vex-import-confirm"
            @click="send(false)"
          />
        </div>
      </template>
    </UModal>
  </UCard>
</template>
