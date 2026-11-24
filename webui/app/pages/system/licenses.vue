<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Politique de licences (F8). La console montre ce qui est décidé
automatiquement (licences permissives autorisées, tout le reste à revoir,
rien d'interdit) ; un administrateur ajoute des décisions globales ou par
projet, tracées dans l'audit. Un essai évalue une expression SPDX.
-->

<script setup lang="ts">
type Decision = 'allowed' | 'review' | 'denied'
interface PolicyRow {
  id: string
  project_id: string | null
  license: string
  decision: Decision
  reason: string | null
  updated_by_username: string | null
  updated_at: string
}
interface PolicyResponse {
  defaults: { version: number, allowed: string[], otherwise: 'review', unknown: 'review' }
  global: PolicyRow[]
  project: PolicyRow[] | null
  projects_with_overrides: { project_id: string, slug: string, name: string, count: number }[]
}

const { t } = useI18n()
useHead({ title: computed(() => t('licenses.title')) })
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()
const isAdmin = computed(() => session.can('admin'))

const data = ref<PolicyResponse | null>(null)
const projects = ref<{ id: string, name: string }[]>([])
const projectId = ref<string>('')
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    data.value = await api<PolicyResponse>('/api/licenses/policy', { query: projectId.value ? { project_id: projectId.value } : {} })
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
async function loadProjects() {
  try {
    projects.value = (await api<{ items: { id: string, name: string }[] }>('/api/projects')).items
  }
  catch {
    projects.value = []
  }
}
onMounted(() => {
  void load()
  void loadProjects()
})
watch(projectId, () => void load())

const decisionItems = computed(() => (['allowed', 'review', 'denied'] as const).map(d => ({ label: t(`licenses.decision.${d}`), value: d })))
const projectItems = computed(() => [{ label: t('licenses.globalOnly'), value: '' }, ...projects.value.map(p => ({ label: p.name, value: p.id }))])
const color = (d: Decision) => ({ allowed: 'success', review: 'warning', denied: 'error' } as const)[d]

// --- ajout d'une décision ---
const form = reactive({ license: '', decision: 'review' as Decision, reason: '', scope: 'global' as 'global' | 'project' })
const saving = ref(false)
async function save() {
  saving.value = true
  try {
    await api('/api/licenses/policy', {
      method: 'PUT',
      body: { license: form.license.trim(), decision: form.decision, reason: form.reason.trim() || undefined, project_id: form.scope === 'project' && projectId.value ? projectId.value : null },
    })
    toast.add({ title: t('licenses.saved'), color: 'success' })
    form.license = ''
    form.reason = ''
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

// --- retrait (modale de la console) ---
const removeTarget = ref<PolicyRow | null>(null)
const removeOpen = ref(false)
const removing = ref(false)
function askRemove(r: PolicyRow) {
  removeTarget.value = r
  removeOpen.value = true
}
async function remove() {
  if (!removeTarget.value) return
  removing.value = true
  try {
    await api(`/api/licenses/policy/${removeTarget.value.id}`, { method: 'DELETE' })
    toast.add({ title: t('licenses.removed'), color: 'success' })
    removeOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    removing.value = false
  }
}

// --- essai d'une expression ---
const trial = reactive({ expression: '', result: null as null | { decision: Decision, source: string }, loading: false })
async function evaluate() {
  trial.loading = true
  try {
    trial.result = await api('/api/licenses/evaluate', { method: 'POST', body: { expression: trial.expression, project_id: projectId.value || null } })
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    trial.loading = false
  }
}
</script>

<template>
  <PageShell :title="t('licenses.title')">
    <template #actions>
      <UButton
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="ghost"
        :loading="loading"
        :aria-label="t('common.refresh')"
        @click="load"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('licenses.help') }}
    </p>

    <div
      v-if="!data && loading"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="data">
      <UCard data-testid="licenses-defaults">
        <template #header>
          <h2 class="font-semibold">
            {{ t('licenses.defaultsTitle') }}
          </h2>
        </template>
        <p class="mb-2 text-sm">
          {{ t('licenses.defaultsHelp') }}
        </p>
        <div class="flex flex-wrap gap-1">
          <UBadge
            v-for="l in data.defaults.allowed"
            :key="l"
            color="success"
            variant="subtle"
            size="sm"
            class="font-mono"
          >
            {{ l }}
          </UBadge>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h2 class="font-semibold">
              {{ t('licenses.policyTitle') }}
            </h2>
            <USelect
              v-model="projectId"
              :items="projectItems"
              class="w-64"
              data-testid="licenses-project"
            />
          </div>
        </template>

        <UAlert
          v-if="!isAdmin"
          color="neutral"
          variant="subtle"
          icon="i-lucide-lock"
          :title="t('licenses.readOnly')"
          class="mb-3"
        />

        <template
          v-for="block in [{ key: 'global', rows: data.global }, ...(data.project ? [{ key: 'project', rows: data.project }] : [])]"
          :key="block.key"
        >
          <h3 class="mt-2 mb-1 text-sm font-medium">
            {{ t(`licenses.scope.${block.key}`) }}
          </h3>
          <p
            v-if="!block.rows.length"
            class="text-sm text-muted"
          >
            {{ t('licenses.noRows') }}
          </p>
          <table
            v-else
            class="w-full text-sm"
          >
            <tbody>
              <tr
                v-for="r in block.rows"
                :key="r.id"
                class="border-t border-default"
                :data-testid="`policy-${r.license}`"
              >
                <td class="py-2 font-mono">
                  {{ r.license }}
                </td>
                <td class="py-2">
                  <UBadge
                    :color="color(r.decision)"
                    variant="subtle"
                  >
                    {{ t(`licenses.decision.${r.decision}`) }}
                  </UBadge>
                </td>
                <td class="py-2 text-xs text-muted">
                  {{ r.reason }}
                  <span v-if="r.updated_by_username"> — {{ r.updated_by_username }}, {{ fmt.date(r.updated_at) }}</span>
                </td>
                <td class="py-2 text-right">
                  <UButton
                    v-if="isAdmin"
                    size="xs"
                    color="error"
                    variant="ghost"
                    icon="i-lucide-trash-2"
                    :aria-label="t('licenses.remove')"
                    @click="askRemove(r)"
                  />
                </td>
              </tr>
            </tbody>
          </table>
        </template>

        <form
          v-if="isAdmin"
          class="mt-4 grid gap-2 md:grid-cols-5"
          data-testid="licenses-form"
          @submit.prevent="save"
        >
          <UInput
            v-model="form.license"
            placeholder="GPL-3.0-only"
            :aria-label="t('licenses.license')"
            required
          />
          <USelect
            v-model="form.decision"
            :items="decisionItems"
          />
          <USelect
            v-model="form.scope"
            :items="[{ label: t('licenses.scope.global'), value: 'global' }, { label: t('licenses.scope.project'), value: 'project', disabled: !projectId }]"
          />
          <UInput
            v-model="form.reason"
            :placeholder="t('licenses.reason')"
            :aria-label="t('licenses.reason')"
          />
          <UButton
            type="submit"
            icon="i-lucide-plus"
            :label="t('licenses.add')"
            :loading="saving"
            :disabled="!form.license.trim()"
          />
        </form>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('licenses.trialTitle') }}
          </h2>
        </template>
        <form
          class="flex flex-wrap items-center gap-2"
          @submit.prevent="evaluate"
        >
          <UInput
            v-model="trial.expression"
            placeholder="(MIT OR GPL-3.0-only) AND Apache-2.0 WITH LLVM-exception"
            class="min-w-80 flex-1 font-mono"
            :aria-label="t('licenses.expression')"
          />
          <UButton
            type="submit"
            :label="t('licenses.evaluate')"
            :loading="trial.loading"
            :disabled="!trial.expression.trim()"
          />
          <UBadge
            v-if="trial.result"
            :color="color(trial.result.decision)"
            variant="subtle"
            data-testid="licenses-trial-result"
          >
            {{ t(`licenses.decision.${trial.result.decision}`) }} · {{ t(`licenses.source.${trial.result.source}`) }}
          </UBadge>
        </form>
      </UCard>
    </template>

    <ConfirmModal
      v-model:open="removeOpen"
      :title="t('licenses.removeTitle')"
      :body="t('licenses.removeBody', { license: removeTarget?.license ?? '' })"
      color="error"
      :loading="removing"
      @confirm="remove"
    />
  </PageShell>
</template>
