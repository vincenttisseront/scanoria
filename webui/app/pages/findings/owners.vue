<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Responsables des résultats (F6) : correspondances entre les responsables lus
dans CODEOWNERS (équipe, identifiant de forge, adresse) et les comptes de la
console, pour tous les projets ou un seul. Un compte voit ensuite ces
résultats dans « Mes résultats ». Sans correspondance, un responsable écrit
comme l'identifiant de la console (ou son adresse) est reconnu directement.
Édition réservée aux administrateurs, auditée.
-->

<script setup lang="ts">
definePageMeta({ role: 'admin' })

const { t } = useI18n()
useHead({ title: computed(() => t('triage.owners.title')) })

const { api, errorMessage } = useApi()
const toast = useToast()

interface Mapping { project_id: string | null, project_slug: string | null, owner: string, user_id: number, username: string, created_at: string }
interface UserRow { id: string, username: string }

const ALL = 'all'
const items = ref<Mapping[]>([])
const users = ref<UserRow[]>([])
const projects = ref<{ project_id: string, project_name: string }[]>([])
const loading = ref(false)
const saving = ref(false)
const form = reactive({ project_id: ALL, owner: '', user_id: '' })

async function load() {
  loading.value = true
  try {
    const [m, u, p] = await Promise.all([
      api<{ items: Mapping[] }>('/api/owner-mappings'),
      api<{ items: UserRow[] }>('/api/users'),
      api<{ projects: { project_id: string, project_name: string }[] }>('/api/findings/summary'),
    ])
    items.value = m.items
    users.value = u.items
    projects.value = p.projects
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const projectItems = computed(() => [{ label: t('triage.rules.allProjects'), value: ALL }, ...projects.value.map(p => ({ label: p.project_name, value: p.project_id }))])
const userItems = computed(() => users.value.map(u => ({ label: u.username, value: u.id })))
const valid = computed(() => /^[^\s]{1,255}$/.test(form.owner.trim()) && /^[0-9]+$/.test(form.user_id))

function payload(m: { project_id: string | null, owner: string, user_id: number }) {
  return { project_id: m.project_id, owner: m.owner, user_id: m.user_id }
}
async function add() {
  saving.value = true
  try {
    await api('/api/owner-mappings', { method: 'POST', body: payload({ project_id: form.project_id === ALL ? null : form.project_id, owner: form.owner.trim(), user_id: Number(form.user_id) }) })
    toast.add({ title: t('triage.owners.added'), color: 'success' })
    form.owner = ''
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}
const removing = ref<string | null>(null)
async function remove(m: Mapping) {
  const key = `${m.project_id}|${m.owner}|${m.user_id}`
  removing.value = key
  try {
    await api('/api/owner-mappings', { method: 'DELETE', body: payload(m) })
    toast.add({ title: t('triage.owners.removed'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    removing.value = null
  }
}
</script>

<template>
  <PageShell :title="t('triage.owners.title')">
    <template #actions>
      <UButton
        to="/findings?mine=true"
        icon="i-lucide-user-check"
        color="neutral"
        variant="ghost"
        :label="t('triage.owners.mine')"
      />
    </template>
    <p class="text-sm text-muted">
      {{ t('triage.owners.help') }}
    </p>

    <UCard>
      <div class="flex flex-wrap items-end gap-3">
        <UFormField :label="t('findings.filters.project')">
          <USelect
            v-model="form.project_id"
            :items="projectItems"
            class="w-56"
          />
        </UFormField>
        <UFormField :label="t('triage.owners.owner')">
          <UInput
            v-model="form.owner"
            class="w-56 font-mono"
            data-testid="owner-input"
          />
        </UFormField>
        <UFormField :label="t('triage.owners.user')">
          <USelect
            v-model="form.user_id"
            :items="userItems"
            class="w-48"
            data-testid="owner-user"
          />
        </UFormField>
        <UButton
          icon="i-lucide-plus"
          :loading="saving"
          :disabled="!valid"
          :label="t('triage.owners.add')"
          data-testid="owner-add"
          @click="add"
        />
      </div>
    </UCard>

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
        v-else-if="!items.length"
        class="text-sm text-muted"
      >
        {{ t('triage.owners.none') }}
      </p>
      <ul
        v-else
        class="divide-y divide-default text-sm"
      >
        <li
          v-for="m in items"
          :key="`${m.project_id}|${m.owner}|${m.user_id}`"
          class="flex flex-wrap items-center justify-between gap-2 py-2"
          data-testid="mapping"
        >
          <span>
            <span class="font-mono">{{ m.owner }}</span> → <span class="font-medium">{{ m.username }}</span>
            <span class="text-xs text-muted"> · {{ m.project_slug ?? t('triage.rules.global') }}</span>
          </span>
          <UButton
            size="xs"
            color="error"
            variant="ghost"
            icon="i-lucide-trash-2"
            :loading="removing === `${m.project_id}|${m.owner}|${m.user_id}`"
            :label="t('triage.owners.remove')"
            @click="remove(m)"
          />
        </li>
      </ul>
    </UCard>
  </PageShell>
</template>
