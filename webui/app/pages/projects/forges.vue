<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Forges (Forgejo d'abord, GitHub ensuite) : ajout avec vérification immédiate,
découverte des dépôts chaque heure (chaque dépôt devient un projet), jeton
remplaçable, retrait. Le jeton n'est jamais réaffiché, seul son indice.
-->

<script setup lang="ts">
import type { Forge } from '~/composables/useProjects'

const { t } = useI18n()
useHead({ title: computed(() => t('projects.forges.title')) })
const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const toast = useToast()
const { api, message, label } = useProjects()

const forges = ref<Forge[] | null>(null)
const loadError = ref('')
async function load() {
  try {
    forges.value = (await api<{ items: Forge[] }>('/api/forges')).items
    loadError.value = ''
  }
  catch (err) {
    loadError.value = message(err)
  }
}
onMounted(load)

// Découverte lancée en arrière-plan à l'ajout : la liste (dépôts, dernière
// découverte, erreur) est relue toutes les 5 s pendant 2 minutes.
let follow: ReturnType<typeof setInterval> | undefined
function followDiscovery() {
  if (follow) clearInterval(follow)
  const until = Date.now() + 120_000
  follow = setInterval(() => {
    if (Date.now() > until) {
      clearInterval(follow)
      follow = undefined
      return
    }
    void load()
  }, 5000)
}
onBeforeUnmount(() => {
  if (follow) clearInterval(follow)
})

// --- Ajout ---
const kinds = computed(() => [
  { label: label('forgeKind', 'forgejo'), value: 'forgejo' },
  { label: label('forgeKind', 'github'), value: 'github' },
])
const form = reactive({ kind: 'forgejo' as 'forgejo' | 'github', name: '', base_url: '', token: '', discovery: true })
const adding = ref(false)
const addError = ref('')
const canAdd = computed(() => form.name.trim() && /^https:\/\//.test(form.base_url.trim()))
watch(() => form.kind, (kind) => {
  if (kind === 'github' && !form.base_url) form.base_url = 'https://github.com'
})
async function add() {
  adding.value = true
  addError.value = ''
  try {
    const res = await api<{ forge: Forge, login: string | null, discovery_started: boolean }>('/api/forges', {
      method: 'POST',
      body: { kind: form.kind, name: form.name.trim(), base_url: form.base_url.trim(), discovery: form.discovery, ...(form.token ? { token: form.token } : {}) },
    })
    toast.add({
      title: t('projects.forges.added', { name: res.forge.name }),
      description: res.discovery_started ? t('projects.forges.discoveryStarted') : undefined,
      color: 'success',
    })
    Object.assign(form, { name: '', base_url: '', token: '' })
    await load()
    if (res.discovery_started) followDiscovery()
  }
  catch (err) {
    addError.value = message(err)
  }
  finally {
    adding.value = false
  }
}

// --- Découverte immédiate ---
const discovering = ref<string | null>(null)
async function discover(f: Forge) {
  discovering.value = f.id
  try {
    const r = await api<{ repos: number, created: string[], error: string | null }>(`/api/forges/${f.id}/discover`, { method: 'POST' })
    if (r.error) toast.add({ title: label('errors', r.error), color: 'error' })
    else toast.add({ title: t('projects.forges.discovered', { repos: r.repos, created: r.created.length }), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    discovering.value = null
  }
}

// --- Modification (jeton, découverte) ---
const editing = ref<Forge | null>(null)
const editOpen = ref(false)
const editToken = ref('')
const editRemove = ref(false)
const editDiscovery = ref(true)
const saving = ref(false)
const editError = ref('')
function openEdit(f: Forge) {
  editing.value = f
  editToken.value = ''
  editRemove.value = false
  editDiscovery.value = f.discovery
  editError.value = ''
  editOpen.value = true
}
async function saveEdit() {
  if (!editing.value) return
  saving.value = true
  editError.value = ''
  try {
    const body: Record<string, unknown> = { discovery: editDiscovery.value }
    if (editRemove.value) body.token = null
    else if (editToken.value) body.token = editToken.value
    await api(`/api/forges/${editing.value.id}`, { method: 'PATCH', body })
    editOpen.value = false
    toast.add({ title: t('projects.forges.saved'), color: 'success' })
    await load()
  }
  catch (err) {
    editError.value = message(err)
  }
  finally {
    saving.value = false
  }
}

// --- Retrait ---
const removing = ref<Forge | null>(null)
const removeOpen = ref(false)
const deleting = ref(false)
function askRemove(f: Forge) {
  removing.value = f
  removeOpen.value = true
}
async function confirmRemove() {
  if (!removing.value) return
  deleting.value = true
  try {
    await api(`/api/forges/${removing.value.id}`, { method: 'DELETE' })
    removeOpen.value = false
    await load()
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
  <PageShell :title="t('projects.forges.title')">
    <template #actions>
      <UButton
        to="/projects"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('projects.title')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('projects.forges.help') }}
    </p>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!forges"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <UCard v-else-if="!forges.length">
      <p class="text-sm text-muted">
        {{ t('projects.forges.empty') }}
      </p>
    </UCard>
    <UCard
      v-for="f in forges ?? []"
      :key="f.id"
    >
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="space-y-1">
          <h2 class="font-semibold">
            {{ f.name }}
            <UBadge
              color="neutral"
              variant="subtle"
              size="sm"
              :label="label('forgeKind', f.kind)"
            />
          </h2>
          <p class="font-mono text-xs text-muted">
            {{ f.base_url }}
          </p>
          <p class="text-sm">
            {{ f.has_token ? t('projects.forges.tokenSet', { hint: f.token_hint ?? '…', user: f.token_user ?? '—' }) : t('projects.forges.noToken') }}
          </p>
          <p class="text-sm text-muted">
            {{ f.discovery && f.has_token ? t('projects.forges.discoveryOn') : t('projects.forges.discoveryOff') }}
            · {{ t('projects.forges.lastDiscovery') }} {{ fmt.date(f.last_discovery_at) }}
            · {{ t('projects.forges.projectCount', { n: f.projects }) }}
          </p>
          <UAlert
            v-if="f.last_error"
            color="warning"
            variant="subtle"
            :title="label('errors', f.last_error)"
          />
        </div>
        <div class="flex flex-wrap gap-2">
          <UButton
            v-if="session.can('operator') && f.has_token"
            icon="i-lucide-radar"
            color="neutral"
            variant="subtle"
            :loading="discovering === f.id"
            :label="t('projects.forges.discoverNow')"
            @click="discover(f)"
          />
          <UButton
            v-if="isAdmin"
            icon="i-lucide-pencil"
            color="neutral"
            variant="ghost"
            :label="t('common.edit')"
            @click="openEdit(f)"
          />
          <UButton
            v-if="isAdmin"
            icon="i-lucide-trash-2"
            color="error"
            variant="ghost"
            :label="t('common.delete')"
            @click="askRemove(f)"
          />
        </div>
      </div>
    </UCard>

    <UCard v-if="isAdmin">
      <template #header>
        <h2 class="font-semibold">
          {{ t('projects.forges.addTitle') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('projects.forges.addHelp') }}
        </p>
      </template>
      <form
        class="grid gap-4 sm:grid-cols-2"
        @submit.prevent="add"
      >
        <UFormField :label="t('projects.forges.kind')">
          <USelect
            v-model="form.kind"
            :items="kinds"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('projects.forges.name')">
          <UInput
            v-model="form.name"
            class="w-full"
            maxlength="100"
          />
        </UFormField>
        <UFormField
          :label="t('projects.forges.url')"
          :help="t('projects.forges.urlHelp')"
        >
          <UInput
            v-model="form.base_url"
            class="w-full"
            placeholder="https://forge.exemple.test"
          />
        </UFormField>
        <UFormField
          :label="t('projects.forges.token')"
          :help="t('projects.forges.tokenHelp')"
        >
          <UInput
            v-model="form.token"
            type="password"
            autocomplete="off"
            class="w-full"
          />
        </UFormField>
        <USwitch
          v-model="form.discovery"
          :label="t('projects.forges.discovery')"
        />
        <div class="flex items-center justify-end gap-2 sm:col-span-2">
          <UAlert
            v-if="addError"
            color="error"
            variant="subtle"
            :title="addError"
          />
          <UButton
            type="submit"
            icon="i-lucide-plug"
            :loading="adding"
            :disabled="!canAdd"
            :label="adding ? t('projects.forges.checking') : t('projects.forges.addButton')"
          />
        </div>
      </form>
    </UCard>

    <UModal
      v-model:open="editOpen"
      :title="t('projects.forges.editTitle', { name: editing?.name ?? '' })"
      :dismissible="!saving"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField
            :label="t('projects.forges.newToken')"
            :help="t('projects.forges.newTokenHelp')"
          >
            <UInput
              v-model="editToken"
              type="password"
              autocomplete="off"
              class="w-full"
              :disabled="editRemove"
            />
          </UFormField>
          <UCheckbox
            v-if="editing?.has_token"
            v-model="editRemove"
            :label="t('projects.forges.removeToken')"
          />
          <USwitch
            v-model="editDiscovery"
            :label="t('projects.forges.discovery')"
          />
          <UAlert
            v-if="editError"
            color="error"
            variant="subtle"
            :title="editError"
          />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="saving"
            :label="t('common.cancel')"
            @click="editOpen = false"
          />
          <UButton
            :loading="saving"
            :label="t('common.save')"
            @click="saveEdit"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="removeOpen"
      color="error"
      :title="t('projects.forges.removeTitle', { name: removing?.name ?? '' })"
      :body="t('projects.forges.removeBody')"
      :confirm-label="t('common.delete')"
      :loading="deleting"
      @confirm="confirmRemove"
    />
  </PageShell>
</template>
