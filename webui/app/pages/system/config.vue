<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Configuration de l'appliance en YAML versionné (J8) : export (profils et
verrous, quality gates, jeux de règles, gravités, règles de tri, projets ;
jamais de secret) et import en deux temps : aperçu des écarts, puis
application confirmée dans une modale, sur la même empreinte. Administrateur.
-->

<script setup lang="ts">
const { t } = useI18n()
useHead({ title: computed(() => t('appconfig.title')) })
const { api, errorMessage } = useApi()
const toast = useToast()
const session = useSession()

interface Change { section: string, key: string, action: 'create' | 'update' | 'unchanged', fields: string[] }
interface Preview { digest: string, changes: Change[], issues: { path: string, message: string }[], summary: Record<string, { create: number, update: number, unchanged: number }> }

const exporting = ref(false)
async function exportConfig() {
  exporting.value = true
  try {
    const res = await api<{ yaml: string, filename: string }>('/api/config/export')
    const url = URL.createObjectURL(new Blob([res.yaml], { type: 'application/yaml' }))
    const a = document.createElement('a')
    a.href = url
    a.download = res.filename
    a.click()
    URL.revokeObjectURL(url)
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    exporting.value = false
  }
}

const MAX_BYTES = 8 * 1024 * 1024
const text = ref('')
const fileName = ref('')
const file = ref<File | null>(null)
watch(file, async (f) => {
  preview.value = null
  error.value = ''
  if (!f) return
  if (f.size > MAX_BYTES) {
    error.value = t('appconfig.tooLarge')
    return
  }
  fileName.value = f.name
  text.value = await f.text()
})

const preview = ref<Preview | null>(null)
const issues = ref<{ path: string, message: string }[]>([])
const loading = ref(false)
const error = ref('')
async function runPreview() {
  loading.value = true
  error.value = ''
  issues.value = []
  try {
    preview.value = await api<Preview>('/api/config/import/preview', { method: 'POST', body: { yaml: text.value } })
  }
  catch (err) {
    preview.value = null
    const d = (err as { data?: { data?: { issues?: { path: string, message: string }[] } } }).data?.data
    issues.value = d?.issues ?? []
    error.value = issues.value.length ? t('appconfig.invalid') : errorMessage(err)
  }
  finally {
    loading.value = false
  }
}

const changes = computed(() => preview.value?.changes.filter(c => c.action !== 'unchanged') ?? [])
const canApply = computed(() => !!preview.value && !preview.value.issues.length && changes.value.length > 0)

const confirmOpen = ref(false)
const applying = ref(false)
async function apply() {
  if (!preview.value) return
  applying.value = true
  try {
    await api('/api/config/import/apply', { method: 'POST', body: { yaml: text.value, digest: preview.value.digest } })
    confirmOpen.value = false
    toast.add({ title: t('appconfig.applied', { n: changes.value.length }), color: 'success' })
    // Nouvel aperçu : tout doit désormais être inchangé.
    await runPreview()
  }
  catch (err) {
    const d = (err as { data?: { data?: { code?: string, issues?: { path: string, message: string }[] } } }).data?.data
    issues.value = d?.issues ?? []
    error.value = d?.code === 'E_CONFIG_DIGEST' ? t('appconfig.digest') : errorMessage(err)
    confirmOpen.value = false
  }
  finally {
    applying.value = false
  }
}
const actionColor = (a: Change['action']) => (a === 'create' ? 'success' : a === 'update' ? 'warning' : 'neutral')
</script>

<template>
  <PageShell :title="t('appconfig.title')">
    <UAlert
      v-if="!session.can('admin')"
      color="neutral"
      variant="subtle"
      :title="t('common.adminOnly')"
    />
    <template v-else>
      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('appconfig.export') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('appconfig.exportHelp') }}
          </p>
        </template>
        <UButton
          icon="i-lucide-download"
          :loading="exporting"
          :label="t('appconfig.exportButton')"
          data-testid="config-export"
          @click="exportConfig"
        />
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('appconfig.import') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('appconfig.importHelp') }}
          </p>
        </template>
        <div class="space-y-4">
          <UFileUpload
            v-model="file"
            accept=".yml,.yaml,application/yaml,text/yaml"
            :label="t('appconfig.file')"
            :description="t('appconfig.fileHelp')"
            class="w-full"
          />
          <div class="flex justify-end">
            <UButton
              icon="i-lucide-eye"
              :loading="loading"
              :disabled="!text"
              :label="t('appconfig.preview')"
              data-testid="config-preview"
              @click="runPreview"
            />
          </div>
          <UAlert
            v-if="error"
            color="error"
            variant="subtle"
            :title="error"
          >
            <template
              v-if="issues.length"
              #description
            >
              <ul class="list-disc ps-5 font-mono text-xs">
                <li
                  v-for="(i, n) in issues"
                  :key="n"
                >
                  {{ i.path }} {{ i.message }}
                </li>
              </ul>
            </template>
          </UAlert>

          <div
            v-if="preview"
            class="space-y-3"
            data-testid="config-diff"
          >
            <p class="text-sm">
              {{ fileName }} · <span class="font-mono text-xs">{{ preview.digest.slice(0, 16) }}</span>
            </p>
            <ul class="flex flex-wrap gap-2">
              <li
                v-for="(s, section) in preview.summary"
                :key="section"
              >
                <UBadge
                  color="neutral"
                  variant="outline"
                  :label="t('appconfig.sectionSummary', { section: t(`appconfig.sections.${section}`), create: s.create, update: s.update, unchanged: s.unchanged })"
                />
              </li>
            </ul>
            <UAlert
              v-if="preview.issues.length"
              color="error"
              variant="subtle"
              :title="t('appconfig.issues', { n: preview.issues.length })"
            >
              <template #description>
                <ul class="list-disc ps-5 font-mono text-xs">
                  <li
                    v-for="(i, n) in preview.issues"
                    :key="n"
                  >
                    {{ i.path }} {{ i.message }}
                  </li>
                </ul>
              </template>
            </UAlert>
            <p
              v-if="!changes.length"
              class="text-sm text-muted"
            >
              {{ t('appconfig.noChange') }}
            </p>
            <ul
              v-else
              class="max-h-80 space-y-1 overflow-y-auto text-sm"
            >
              <li
                v-for="c in changes"
                :key="`${c.section}/${c.key}`"
                class="flex flex-wrap items-center gap-2"
              >
                <UBadge
                  :color="actionColor(c.action)"
                  variant="subtle"
                  size="sm"
                  :label="t(`appconfig.actions.${c.action}`)"
                />
                <span class="text-muted">{{ t(`appconfig.sections.${c.section}`) }}</span>
                <span class="font-mono">{{ c.key }}</span>
                <span
                  v-if="c.fields.length"
                  class="text-xs text-muted"
                >{{ c.fields.join(', ') }}</span>
              </li>
            </ul>
            <div class="flex justify-end">
              <UButton
                :disabled="!canApply"
                :label="t('appconfig.apply')"
                data-testid="config-apply"
                @click="confirmOpen = true"
              />
            </div>
          </div>
        </div>
      </UCard>

      <ConfirmModal
        v-model:open="confirmOpen"
        color="warning"
        :title="t('appconfig.confirmTitle')"
        :body="t('appconfig.confirmBody', { n: changes.length })"
        :confirm-label="t('appconfig.apply')"
        :loading="applying"
        :ack="t('appconfig.confirmAck')"
        @confirm="apply"
      />
    </template>
  </PageShell>
</template>
