<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Profils d'analyse (G8) : hiérarchie entreprise → équipe → projet, verrous
hérités, création (administrateur), profils archivés sur demande.
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'
import { SLUG_RE } from '#shared/analysis'

const { t, te } = useI18n()
useHead({ title: computed(() => t('profiles.title')) })

const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

function message(err: unknown): string {
  const { code } = profileErrorDetails(err)
  return code && te(`profiles.errors.${code}`) ? t(`profiles.errors.${code}`) : errorMessage(err)
}

const profiles = ref<ProfileRow[]>([])
const showArchived = ref(false)
const loading = ref(false)
const loadError = ref('')
async function load() {
  loading.value = true
  try {
    profiles.value = (await api<{ items: ProfileRow[] }>(`/api/profiles${showArchived.value ? '?archived=1' : ''}`)).items
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
watch(showArchived, load)

/** Profils dans l'ordre de la hiérarchie : chaque enfant sous son parent. */
const ordered = computed(() => {
  const byParent = new Map<string | null, ProfileRow[]>()
  for (const p of profiles.value) {
    const k = profiles.value.some(x => x.id === p.parent_id) ? p.parent_id : null
    byParent.set(k, [...(byParent.get(k) ?? []), p])
  }
  const out: (ProfileRow & { depth: number })[] = []
  const walk = (parent: string | null, depth: number) => {
    for (const p of (byParent.get(parent) ?? []).sort((a, b) => a.slug.localeCompare(b.slug))) {
      out.push({ ...p, depth })
      if (depth < 3) walk(p.id, depth + 1)
    }
  }
  walk(null, 0)
  return out
})

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')
const UIcon = resolveComponent('UIcon')
const columns = computed<TableColumn<ProfileRow & { depth: number }>[]>(() => [
  {
    accessorKey: 'slug',
    header: t('profiles.slug'),
    cell: ({ row }) => h('div', { class: 'flex items-center gap-2', style: { paddingInlineStart: `${row.original.depth * 1.25}rem` } }, [
      row.original.depth ? h(UIcon, { name: 'i-lucide-corner-down-right', class: 'size-4 text-muted' }) : null,
      h(ULink, { to: `/profiles/${row.original.id}`, class: 'font-medium' }, () => row.original.slug),
      row.original.builtin ? h(UBadge, { color: 'neutral', variant: 'subtle', size: 'sm', label: t('profiles.builtin') }) : null,
      row.original.archived_at ? h(UBadge, { color: 'warning', variant: 'subtle', size: 'sm', label: t('profiles.archived') }) : null,
      hasLocks(row.original) ? h(UIcon, { 'name': 'i-lucide-lock', 'class': 'size-4 text-muted', 'aria-label': t('profiles.hasLocks') }) : null,
    ]),
  },
  { accessorKey: 'level', header: t('profiles.level'), cell: ({ row }) => t(`profiles.levels.${row.original.level}`) },
  { accessorKey: 'projects', header: t('profiles.projects') },
  {
    accessorKey: 'updated_at',
    header: t('profiles.updated'),
    cell: ({ row }) => row.original.updated_by_username
      ? `${fmt.date(row.original.updated_at)} ${t('profiles.by', { user: row.original.updated_by_username })}`
      : fmt.date(row.original.updated_at),
  },
])
function hasLocks(p: ProfileRow): boolean {
  const l = p.locks
  return !!l && (l.ai_opt_out || l.required_categories.length > 0 || l.required_modules.length > 0 || Object.keys(l.gate_floor).length > 0)
}

// --- Création ---
const createOpen = ref(false)
const creating = ref(false)
const ROOT = '__root__'
const form = reactive({ slug: '', level: 'enterprise' as ProfileLevel, parent_id: ROOT, description: '' })
const levelItems = computed(() => PROFILE_LEVELS.map(l => ({ label: t(`profiles.levels.${l}`), value: l })))
const rank: Record<ProfileLevel, number> = { enterprise: 0, team: 1, project: 2 }
const parentItems = computed(() => form.level === 'enterprise'
  ? [{ label: t('profiles.noParent'), value: ROOT }]
  : profiles.value.filter(p => !p.archived_at && rank[p.level] < rank[form.level]).map(p => ({ label: `${p.slug} (${t(`profiles.levels.${p.level}`)})`, value: p.id })))
watch(() => form.level, () => {
  form.parent_id = parentItems.value[0]?.value ?? ROOT
})
const valid = computed(() => SLUG_RE.test(form.slug) && (form.level === 'enterprise' || form.parent_id !== ROOT))
function openCreate() {
  Object.assign(form, { slug: '', level: 'enterprise', parent_id: ROOT, description: '' })
  createOpen.value = true
}
async function create() {
  creating.value = true
  try {
    const p = await api<ProfileRow>('/api/profiles', {
      method: 'POST',
      body: {
        slug: form.slug, level: form.level, parent_id: form.parent_id === ROOT ? null : form.parent_id,
        ...(form.description.trim() ? { description: form.description.trim() } : {}),
      },
    })
    toast.add({ title: t('profiles.created'), color: 'success' })
    createOpen.value = false
    await navigateTo(`/profiles/${p.id}`)
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    creating.value = false
  }
}
</script>

<template>
  <PageShell :title="t('profiles.title')">
    <template #actions>
      <USwitch
        v-model="showArchived"
        :label="t('profiles.showArchived')"
      />
      <UButton
        v-if="session.can('admin')"
        icon="i-lucide-plus"
        :label="t('profiles.create')"
        data-testid="profile-create"
        @click="openCreate"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <p class="text-sm text-muted">
      {{ t('profiles.intro') }}
    </p>

    <UTable
      :data="ordered"
      :columns="columns"
      :loading="loading"
      :empty="t('profiles.empty')"
    />

    <UModal
      v-model:open="createOpen"
      :title="t('profiles.createTitle')"
      :dismissible="!creating"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField
            :label="t('profiles.slug')"
            :help="t('profiles.slugHelp')"
          >
            <UInput
              v-model="form.slug"
              class="w-full"
              autocomplete="off"
              data-testid="profile-slug"
            />
          </UFormField>
          <UFormField
            :label="t('profiles.level')"
            :help="t('profiles.levelHelp')"
          >
            <USelect
              v-model="form.level"
              :items="levelItems"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('profiles.parent')">
            <USelect
              v-model="form.parent_id"
              :items="parentItems"
              class="w-full"
              :disabled="form.level === 'enterprise'"
            />
          </UFormField>
          <UFormField :label="t('profiles.description')">
            <UTextarea
              v-model="form.description"
              class="w-full"
              :rows="2"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="creating"
            :label="t('common.cancel')"
            @click="createOpen = false"
          />
          <UButton
            :loading="creating"
            :disabled="!valid"
            :label="t('common.create')"
            data-testid="profile-create-confirm"
            @click="create"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
