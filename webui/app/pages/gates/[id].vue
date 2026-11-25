<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'un quality gate : formulaire généré depuis GateRules (champs H4 et G13
verrouillés, avec la raison), projets affectés, affectation et suppression.
-->

<script setup lang="ts">
import { GateRules, SEVERITIES } from '#shared/analysis'

const { t, te } = useI18n()
const route = useRoute()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface GateDetail {
  id: string
  slug: string
  builtin: boolean
  rules: GateRules
  updated_at: string
  updated_by_username: string | null
  project_list: { id: string, slug: string, name: string }[]
}

const id = computed(() => String(route.params.id))
const gate = ref<GateDetail | null>(null)
const rules = ref<Record<string, unknown>>({})
const loading = ref(false)
const fields = gateFields()
const canEdit = computed(() => session.can('admin'))

useHead({ title: computed(() => gate.value ? `${t('gates.title')} · ${gate.value.slug}` : t('gates.title')) })

function message(err: unknown): string {
  const code = gateErrorCode(err)
  return code && te(`gates.errors.${code}`) ? t(`gates.errors.${code}`) : errorMessage(err)
}

const loadError = ref('')
async function load() {
  loading.value = true
  try {
    gate.value = await api<GateDetail>(`/api/gates/${id.value}`)
    rules.value = { ...GateRules.parse(gate.value.rules) }
    loadError.value = ''
  }
  catch (err) {
    loadError.value = message(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const NONE = '__none__'
const severityItems = computed(() => [
  ...SEVERITIES.map(s => ({ label: t(`gates.severities.${s}`), value: s })),
  { label: t('gates.none'), value: NONE },
])
function severityModel(key: string) {
  return computed({
    get: () => (rules.value[key] === null ? NONE : String(rules.value[key])),
    set: (v: string) => {
      rules.value[key] = v === NONE ? null : v
    },
  })
}
const severityModels = Object.fromEntries(fields.filter(f => f.kind === 'severity').map(f => [f.key, severityModel(f.key)]))

/**
 * Nombre facultatif (G16, feed_max_age_days) : la valeur null a son propre
 * libellé (« seulement signaler »), proposé quand gates.fields.<clé>_null existe.
 */
const lastNumber: Record<string, number> = {}
function nullToggle(key: string, min: number) {
  return computed({
    get: () => rules.value[key] === null,
    set: (isNull: boolean) => {
      if (isNull) {
        if (typeof rules.value[key] === 'number') lastNumber[key] = rules.value[key] as number
        rules.value[key] = null
      }
      else {
        rules.value[key] = lastNumber[key] ?? Math.max(min, 7)
      }
    },
  })
}
const nullModels = Object.fromEntries(fields.flatMap(f => f.kind === 'number' && f.nullable && te(`gates.fields.${f.key}_null`) ? [[f.key, nullToggle(f.key, f.min)]] : []))

const parsed = computed(() => GateRules.safeParse(rules.value))
const dirty = computed(() => !!gate.value && JSON.stringify(GateRules.parse(gate.value.rules)) !== JSON.stringify(parsed.value.success ? parsed.value.data : null))
const saving = ref(false)
async function save() {
  if (!parsed.value.success) return
  saving.value = true
  try {
    await api(`/api/gates/${id.value}`, { method: 'PATCH', body: { rules: parsed.value.data } })
    toast.add({ title: t('gates.saved'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

// --- Affectation ---
const assignOpen = ref(false)
const assigning = ref(false)
const projectItems = ref<{ label: string, value: string }[]>([])
const projectId = ref('')
const projectsUnavailable = ref(false)
async function openAssign() {
  projectId.value = ''
  projectsUnavailable.value = false
  assignOpen.value = true
  try {
    const res = await api<{ items: { id: string, name: string, slug: string }[] }>('/api/projects')
    projectItems.value = res.items.map(p => ({ label: `${p.name} (${p.slug})`, value: p.id }))
  }
  catch {
    projectsUnavailable.value = true
  }
}
async function assign() {
  assigning.value = true
  try {
    await api(`/api/gates/${id.value}/assign`, { method: 'POST', body: { project_id: projectId.value } })
    toast.add({ title: t('gates.assigned'), color: 'success' })
    assignOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    assigning.value = false
  }
}

// --- Suppression ---
const deleteOpen = ref(false)
const deleting = ref(false)
async function remove() {
  deleting.value = true
  try {
    await api(`/api/gates/${id.value}`, { method: 'DELETE' })
    toast.add({ title: t('gates.deleted'), color: 'success' })
    deleteOpen.value = false
    await navigateTo('/gates')
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    deleting.value = false
  }
}
</script>

<template>
  <PageShell :title="gate ? `${t('gates.title')} · ${gate.slug}` : t('gates.title')">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <template #actions>
      <UButton
        v-if="canEdit && gate && !gate.builtin"
        color="error"
        variant="ghost"
        icon="i-lucide-trash"
        :label="t('common.delete')"
        @click="deleteOpen = true"
      />
    </template>

    <div
      v-if="loading && !gate"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="gate">
      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <h2 class="font-semibold">
              {{ t('gates.rulesTitle') }}
              <UBadge
                v-if="gate.builtin"
                class="ml-2"
                color="neutral"
                variant="subtle"
                size="sm"
                :label="t('gates.builtin')"
              />
            </h2>
            <span class="text-xs text-muted">
              {{ t('gates.updated') }} : {{ fmt.date(gate.updated_at) }}
              <template v-if="gate.updated_by_username">{{ t('gates.by', { user: gate.updated_by_username }) }}</template>
            </span>
          </div>
        </template>

        <p
          v-if="!canEdit"
          class="mb-4 text-sm text-muted"
        >
          {{ t('gates.readOnly') }}
        </p>

        <div class="grid gap-5 md:grid-cols-2">
          <UFormField
            v-for="f in fields"
            :key="f.key"
            :label="t(`gates.fields.${f.key}`)"
            :help="t(`gates.fields.${f.key}_help`)"
            :data-testid="`rule-${f.key}`"
          >
            <USwitch
              v-if="f.kind === 'boolean'"
              v-model="(rules[f.key] as boolean)"
              :disabled="!canEdit"
            />
            <div
              v-else-if="f.kind === 'number' && nullModels[f.key]"
              class="flex flex-wrap items-center gap-3"
            >
              <UInputNumber
                v-if="rules[f.key] !== null"
                v-model="(rules[f.key] as number)"
                :min="f.min"
                :disabled="!canEdit"
              />
              <UCheckbox
                v-model="nullModels[f.key]!.value"
                :label="t(`gates.fields.${f.key}_null`)"
                :disabled="!canEdit"
                :data-testid="`rule-${f.key}-null`"
              />
            </div>
            <UInputNumber
              v-else-if="f.kind === 'number'"
              v-model="(rules[f.key] as number)"
              :min="f.min"
              :disabled="!canEdit"
            />
            <USelect
              v-else-if="f.kind === 'severity'"
              v-model="severityModels[f.key]!.value"
              :items="severityItems"
              :disabled="!canEdit"
              class="min-w-48"
            />
            <div
              v-else
              class="flex items-center gap-2 text-sm"
              data-testid="rule-locked"
            >
              <USwitch
                :model-value="true"
                disabled
              />
              <UIcon name="i-lucide-lock" />
              <span class="text-muted">{{ t('gates.lockedBy', { rule: f.reason }) }}</span>
            </div>
          </UFormField>
        </div>

        <template
          v-if="canEdit"
          #footer
        >
          <div class="flex justify-end">
            <UButton
              :loading="saving"
              :disabled="!dirty || !parsed.success"
              :label="t('common.save')"
              data-testid="gate-save"
              @click="save"
            />
          </div>
        </template>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex items-center justify-between">
            <h2 class="font-semibold">
              {{ t('gates.projectsTitle') }}
            </h2>
            <UButton
              v-if="canEdit"
              size="sm"
              variant="soft"
              icon="i-lucide-link"
              :label="t('gates.assign')"
              @click="openAssign"
            />
          </div>
        </template>
        <p
          v-if="!gate.project_list.length"
          class="text-sm text-muted"
        >
          {{ t('gates.noProjects') }}
        </p>
        <ul
          v-else
          class="space-y-1 text-sm"
        >
          <li
            v-for="p in gate.project_list"
            :key="p.id"
          >
            <ULink :to="`/gates/projects/${p.id}`">
              {{ p.name }}
            </ULink>
            <span class="text-muted"> ({{ p.slug }})</span>
          </li>
        </ul>
      </UCard>
    </template>

    <UModal
      v-model:open="assignOpen"
      :title="t('gates.assignTitle')"
      :dismissible="!assigning"
    >
      <template #body>
        <div class="space-y-3">
          <p class="text-sm text-muted">
            {{ t('gates.assignHelp') }}
          </p>
          <p
            v-if="projectsUnavailable"
            class="text-sm text-warning"
          >
            {{ t('gates.projectsUnavailable') }}
          </p>
          <UFormField
            v-else
            :label="t('gates.project')"
          >
            <USelect
              v-model="projectId"
              :items="projectItems"
              class="w-full"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="assigning"
            :label="t('common.cancel')"
            @click="assignOpen = false"
          />
          <UButton
            :loading="assigning"
            :disabled="!projectId"
            :label="t('common.confirm')"
            @click="assign"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="deleteOpen"
      :title="t('gates.deleteTitle')"
      :body="t('gates.deleteBody', { slug: gate?.slug ?? '' })"
      color="error"
      :loading="deleting"
      :confirm-label="t('common.delete')"
      @confirm="remove"
    />
  </PageShell>
</template>
