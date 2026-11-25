<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Reprise de l'existant (J5) : configurations du dépôt (.gitleaks.toml,
.trivyignore, osv-scanner.toml, # nosec…) et statuts de tri d'une instance
SonarQube, Dependency-Track ou DefectDojo. Aperçu d'abord (rien n'est écrit),
puis application confirmée : chaque entrée devient une demande d'exception,
approuvée ensuite par un administrateur. Le jeton d'administration de
l'instance est chiffré le temps de l'aperçu puis effacé.
-->

<script setup lang="ts">
const props = defineProps<{ projectId: string, isGit: boolean }>()
const open = defineModel<boolean>('open', { default: false })
const emit = defineEmits<{ applied: [] }>()
const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()

interface ImportedRequest { kind: string, target: Record<string, unknown>, reason: string, expires_on: string, source: string, status: string }
interface Report {
  outcome: { created: unknown[], skipped: unknown[] }
  requests: ImportedRequest[]
  unsupported: { source: string, entry: string }[]
  sources: { source: string, requests: number, unsupported: number }[]
  import_token: string | null
  expires_on: string
}

const NO_INSTANCE = '__none__'
const form = reactive({ repo: true, kind: NO_INSTANCE, base_url: '', project: '', token: '', expires_on: '' })
const kindItems = computed(() => [
  { label: t('imports.noInstance'), value: NO_INSTANCE },
  { label: 'SonarQube', value: 'sonarqube' },
  { label: 'Dependency-Track', value: 'dependency-track' },
  { label: 'DefectDojo', value: 'defectdojo' },
])
const report = ref<Report | null>(null)
const loading = ref(false)
const applying = ref(false)
const error = ref('')

watch(open, (v) => {
  if (!v) return
  Object.assign(form, { repo: props.isGit, kind: NO_INSTANCE, base_url: '', project: '', token: '', expires_on: '' })
  report.value = null
  error.value = ''
})

const hasInstance = computed(() => form.kind !== NO_INSTANCE)
const valid = computed(() => (form.repo || hasInstance.value)
  && (!hasInstance.value || (form.base_url.startsWith('https://') && form.project.trim().length > 0 && form.token.length >= 8)))
const instance = () => (hasInstance.value ? { kind: form.kind, base_url: form.base_url.trim(), project: form.project.trim() } : undefined)

function message(err: unknown): string {
  const { code } = profileErrorDetails(err)
  return code && te(`imports.errors.${code}`) ? t(`imports.errors.${code}`) : errorMessage(err)
}

async function runPreview() {
  loading.value = true
  error.value = ''
  try {
    const inst = instance()
    report.value = await api<Report>(`/api/projects/${props.projectId}/imports/preview`, {
      method: 'POST',
      body: { repo: form.repo, ...(inst ? { instance: { ...inst, token: form.token } } : {}), ...(form.expires_on ? { expires_on: form.expires_on } : {}) },
    })
    // Le jeton n'est plus nécessaire côté navigateur : il est chiffré dans l'appliance.
    form.token = ''
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    loading.value = false
  }
}

async function apply() {
  if (!report.value) return
  applying.value = true
  try {
    const inst = instance()
    const res = await api<Report>(`/api/projects/${props.projectId}/imports/apply`, {
      method: 'POST',
      body: {
        repo: form.repo, ...(inst ? { instance: inst } : {}), ...(report.value.import_token ? { import_token: report.value.import_token } : {}),
        expires_on: report.value.expires_on,
      },
    })
    toast.add({ title: t('imports.applied', { n: res.outcome.created.length }), color: 'success' })
    open.value = false
    emit('applied')
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    applying.value = false
  }
}

const newCount = computed(() => report.value?.requests.filter(r => r.status === 'new').length ?? 0)
const targetLabel = (r: ImportedRequest) => {
  const v = r.target
  return String(v.glob ?? v.rule_id ?? v.vuln_id ?? v.module_id ?? v.finding_id ?? '') + (v.tool ? ` (${String(v.tool)})` : v.package ? ` (${String(v.package)})` : '')
}
const statusColor = (s: string) => (s === 'new' ? 'success' : s === 'duplicate' ? 'neutral' : 'warning')
</script>

<template>
  <UModal
    v-model:open="open"
    :title="t('imports.title')"
    :description="t('imports.help')"
    :dismissible="!loading && !applying"
    :ui="{ content: 'sm:max-w-3xl' }"
  >
    <template #body>
      <div class="space-y-4">
        <USwitch
          v-model="form.repo"
          :disabled="!isGit || !!report"
          :label="t('imports.repo')"
          :description="isGit ? t('imports.repoHelp') : t('imports.repoArchive')"
        />
        <div class="grid gap-3 sm:grid-cols-2">
          <UFormField :label="t('imports.instance')">
            <USelect
              v-model="form.kind"
              :items="kindItems"
              class="w-full"
              :disabled="!!report"
              data-testid="import-kind"
            />
          </UFormField>
          <UFormField
            :label="t('imports.expires')"
            :help="t('imports.expiresHelp')"
          >
            <UInput
              v-model="form.expires_on"
              type="date"
              class="w-full"
              :disabled="!!report"
            />
          </UFormField>
          <template v-if="hasInstance">
            <UFormField :label="t('imports.baseUrl')">
              <UInput
                v-model="form.base_url"
                class="w-full"
                placeholder="https://sonarqube.analyse.exemple.test"
                :disabled="!!report"
              />
            </UFormField>
            <UFormField
              :label="t(`imports.project.${form.kind}`)"
            >
              <UInput
                v-model="form.project"
                class="w-full font-mono"
                :disabled="!!report"
              />
            </UFormField>
            <UFormField
              v-if="!report"
              :label="t('imports.token')"
              :help="t('imports.tokenHelp')"
              class="sm:col-span-2"
            >
              <UInput
                v-model="form.token"
                type="password"
                autocomplete="off"
                class="w-full"
              />
            </UFormField>
          </template>
        </div>

        <UAlert
          v-if="error"
          color="error"
          variant="subtle"
          :title="error"
        />
        <div
          v-if="loading"
          class="flex items-center gap-2 text-sm text-muted"
          role="status"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-4 animate-spin"
          />
          {{ t('imports.reading') }}
        </div>

        <div
          v-if="report"
          class="space-y-3"
          data-testid="import-report"
        >
          <p class="text-sm">
            {{ t('imports.summary', { n: newCount, total: report.requests.length, until: report.expires_on }) }}
          </p>
          <ul class="flex flex-wrap gap-2 text-xs">
            <li
              v-for="s in report.sources"
              :key="s.source"
            >
              <UBadge
                color="neutral"
                variant="outline"
                :label="`${s.source} · ${s.requests}`"
              />
            </li>
          </ul>
          <div class="max-h-72 overflow-y-auto rounded-md border border-default">
            <table class="w-full text-sm">
              <thead class="bg-elevated text-left text-xs text-muted">
                <tr>
                  <th class="px-2 py-1">
                    {{ t('imports.col.target') }}
                  </th>
                  <th class="px-2 py-1">
                    {{ t('imports.col.source') }}
                  </th>
                  <th class="px-2 py-1">
                    {{ t('imports.col.status') }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(r, i) in report.requests"
                  :key="i"
                  class="border-t border-default"
                >
                  <td class="px-2 py-1">
                    <span class="text-muted">{{ t(`imports.kinds.${r.kind}`) }}</span>
                    <span class="ms-1 font-mono text-xs break-all">{{ targetLabel(r) }}</span>
                  </td>
                  <td class="px-2 py-1 font-mono text-xs">
                    {{ r.source }}
                  </td>
                  <td class="px-2 py-1">
                    <UBadge
                      :color="statusColor(r.status)"
                      variant="subtle"
                      size="sm"
                      :label="t(`imports.status.${r.status}`)"
                    />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <details v-if="report.unsupported.length">
            <summary class="cursor-pointer text-sm text-warning">
              {{ t('imports.unsupported', { n: report.unsupported.length }) }}
            </summary>
            <ul class="mt-1 list-disc ps-5 font-mono text-xs">
              <li
                v-for="(u, i) in report.unsupported"
                :key="i"
              >
                {{ u.source }} : {{ u.entry }}
              </li>
            </ul>
          </details>
          <p class="text-xs text-muted">
            {{ t('imports.approval') }}
          </p>
        </div>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton
          color="neutral"
          variant="ghost"
          :disabled="loading || applying"
          :label="t('common.cancel')"
          @click="open = false"
        />
        <UButton
          v-if="!report"
          icon="i-lucide-eye"
          :loading="loading"
          :disabled="!valid"
          :label="t('imports.preview')"
          data-testid="import-preview"
          @click="runPreview"
        />
        <UButton
          v-else
          :loading="applying"
          :disabled="!newCount"
          :label="t('imports.apply', { n: newCount })"
          data-testid="import-apply"
          @click="apply"
        />
      </div>
    </template>
  </UModal>
</template>
