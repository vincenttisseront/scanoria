<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Gestion des utilisateurs locaux (administrateurs).
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'
import { ROLES, passwordSchema, userCreateSchema, type Role } from '#shared/schemas'

definePageMeta({ role: 'admin' })

const { t } = useI18n()
useHead({ title: computed(() => t('users.title')) })

const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface UserRow {
  id: string
  username: string
  display_name: string | null
  email: string | null
  role: Role
  locale: 'fr' | 'en'
  is_active: boolean
  kind?: 'human' | 'agent' | 'bot'
  must_change_password: boolean
  locked_until: string | null
  last_login_at: string | null
}

const users = ref<UserRow[]>([])
const loading = ref(false)
const loadError = ref('')
async function load() {
  loading.value = true
  try {
    users.value = (await api<{ items: UserRow[] }>('/api/users')).items
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

const roleItems = computed(() => ROLES.map(r => ({ label: t(`roles.${r}`), value: r })))
const localeItems = [{ label: 'Français', value: 'fr' }, { label: 'English', value: 'en' }]

// --- Création ---
const createOpen = ref(false)
const createForm = reactive({ username: '', display_name: '', email: '', role: 'viewer' as Role, locale: 'fr' as 'fr' | 'en', password: '' })
const creating = ref(false)
const createBody = computed(() => ({
  username: createForm.username.trim(),
  display_name: createForm.display_name.trim() || null,
  email: createForm.email.trim() || null,
  role: createForm.role,
  locale: createForm.locale,
  password: createForm.password,
}))
const createValid = computed(() => userCreateSchema.safeParse(createBody.value).success)
function openCreate() {
  Object.assign(createForm, { username: '', display_name: '', email: '', role: 'viewer', locale: 'fr', password: '' })
  createOpen.value = true
}
async function create() {
  creating.value = true
  try {
    await api('/api/users', { method: 'POST', body: createBody.value })
    toast.add({ title: t('users.created'), color: 'success' })
    createOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    creating.value = false
    createForm.password = ''
  }
}

// --- Modification ---
const editOpen = ref(false)
const editing = ref<UserRow | null>(null)
const editForm = reactive({ display_name: '', email: '', role: 'viewer' as Role, locale: 'fr' as 'fr' | 'en', is_active: true, kind: 'human' as 'human' | 'agent' | 'bot' })
const kindItems = computed(() => (['human', 'agent', 'bot'] as const).map(k => ({ label: t(`triage.userKind.${k}`), value: k })))
const saving = ref(false)
function openEdit(u: UserRow) {
  editing.value = u
  Object.assign(editForm, { display_name: u.display_name ?? '', email: u.email ?? '', role: u.role, locale: u.locale, is_active: u.is_active, kind: u.kind ?? 'human' })
  editOpen.value = true
}
async function saveEdit() {
  if (!editing.value) return
  saving.value = true
  try {
    await api(`/api/users/${editing.value.id}`, {
      method: 'PATCH',
      body: {
        display_name: editForm.display_name.trim() || null,
        email: editForm.email.trim() || null,
        role: editForm.role,
        locale: editForm.locale,
        is_active: editForm.is_active,
        kind: editForm.kind,
      },
    })
    toast.add({ title: t('users.updated'), color: 'success' })
    editOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

// --- Mot de passe ---
const resetOpen = ref(false)
const resetUser = ref<UserRow | null>(null)
const resetForm = reactive({ password: '', must_change_password: true })
const resetting = ref(false)
const resetValid = computed(() => passwordSchema.safeParse(resetForm.password).success)
function openReset(u: UserRow) {
  resetUser.value = u
  Object.assign(resetForm, { password: '', must_change_password: true })
  resetOpen.value = true
}
async function doReset() {
  if (!resetUser.value) return
  resetting.value = true
  try {
    await api(`/api/users/${resetUser.value.id}/password`, { method: 'POST', body: { ...resetForm } })
    toast.add({ title: t('users.passwordReset'), color: 'success' })
    resetOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    resetting.value = false
    resetForm.password = ''
  }
}

// --- Suppression ---
const deleteOpen = ref(false)
const deleteUser = ref<UserRow | null>(null)
const deleting = ref(false)
async function doDelete() {
  if (!deleteUser.value) return
  deleting.value = true
  try {
    await api(`/api/users/${deleteUser.value.id}`, { method: 'DELETE' })
    toast.add({ title: t('users.deleted'), color: 'success' })
    deleteOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    deleting.value = false
  }
}

const UBadge = resolveComponent('UBadge')
const UDropdownMenu = resolveComponent('UDropdownMenu')
const UButton = resolveComponent('UButton')

const columns = computed<TableColumn<UserRow>[]>(() => [
  {
    accessorKey: 'username',
    header: t('users.username'),
    cell: ({ row }) => h('div', [
      h('div', { class: 'font-medium' }, row.original.username),
      row.original.display_name ? h('div', { class: 'text-xs text-muted' }, row.original.display_name) : null,
    ]),
  },
  { accessorKey: 'role', header: t('users.role'), cell: ({ row }) => t(`roles.${row.original.role}`) },
  {
    accessorKey: 'is_active',
    header: t('users.active'),
    cell: ({ row }) => {
      const u = row.original
      const badges = [h(UBadge, { color: u.is_active ? 'success' : 'neutral', variant: 'subtle', label: u.is_active ? t('common.yes') : t('common.no') })]
      if (u.locked_until && Date.parse(u.locked_until) > Date.now()) {
        badges.push(h(UBadge, { color: 'warning', variant: 'subtle', class: 'ml-1', label: t('users.locked', { date: fmt.date(u.locked_until) }) }))
      }
      if (u.must_change_password) badges.push(h(UBadge, { color: 'info', variant: 'subtle', class: 'ml-1', label: t('users.mustChange') }))
      return h('div', badges)
    },
  },
  { accessorKey: 'last_login_at', header: t('users.lastLogin'), cell: ({ row }) => fmt.date(row.original.last_login_at) },
  {
    id: 'actions',
    header: t('common.actions'),
    cell: ({ row }) => h(UDropdownMenu, {
      items: [
        [
          { label: t('common.edit'), icon: 'i-lucide-pencil', onSelect: () => openEdit(row.original) },
          { label: t('users.resetPassword'), icon: 'i-lucide-key-round', onSelect: () => openReset(row.original) },
        ],
        [{
          label: t('common.delete'),
          icon: 'i-lucide-trash-2',
          color: 'error',
          disabled: Number(row.original.id) === session.state.value.user?.id,
          onSelect: () => {
            deleteUser.value = row.original
            deleteOpen.value = true
          },
        }],
      ],
      content: { align: 'end' },
    }, () => h(UButton, { 'icon': 'i-lucide-ellipsis-vertical', 'color': 'neutral', 'variant': 'ghost', 'aria-label': t('common.actions') })),
  },
])
</script>

<template>
  <PageShell :title="t('users.title')">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <template #actions>
      <UButton
        icon="i-lucide-user-plus"
        :label="t('users.create')"
        @click="openCreate"
      />
    </template>

    <UCard>
      <UTable
        :data="users"
        :columns="columns"
        :loading="loading"
        :empty="t('common.none')"
      />
    </UCard>

    <UModal
      v-model:open="createOpen"
      :title="t('users.createTitle')"
      :dismissible="!creating"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField
            :label="t('users.username')"
            :help="t('users.usernameHelp')"
            required
          >
            <UInput
              v-model="createForm.username"
              autocomplete="off"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('users.displayName')">
            <UInput
              v-model="createForm.display_name"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('users.email')">
            <UInput
              v-model="createForm.email"
              type="email"
              placeholder="nom@exemple.test"
              class="w-full"
            />
          </UFormField>
          <div class="grid grid-cols-2 gap-4">
            <UFormField :label="t('users.role')">
              <USelect
                v-model="createForm.role"
                :items="roleItems"
                class="w-full"
              />
            </UFormField>
            <UFormField :label="t('users.locale')">
              <USelect
                v-model="createForm.locale"
                :items="localeItems"
                class="w-full"
              />
            </UFormField>
          </div>
          <UFormField
            :label="t('users.initialPassword')"
            required
          >
            <UInput
              v-model="createForm.password"
              type="password"
              autocomplete="new-password"
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
            :disabled="creating"
            :label="t('common.cancel')"
            @click="createOpen = false"
          />
          <UButton
            :disabled="!createValid"
            :loading="creating"
            :label="t('common.create')"
            @click="create"
          />
        </div>
      </template>
    </UModal>

    <UModal
      v-model:open="editOpen"
      :title="t('users.editTitle', { username: editing?.username ?? '' })"
      :dismissible="!saving"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField :label="t('users.displayName')">
            <UInput
              v-model="editForm.display_name"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('users.email')">
            <UInput
              v-model="editForm.email"
              type="email"
              class="w-full"
            />
          </UFormField>
          <div class="grid grid-cols-2 gap-4">
            <UFormField :label="t('users.role')">
              <USelect
                v-model="editForm.role"
                :items="roleItems"
                class="w-full"
              />
            </UFormField>
            <UFormField :label="t('users.locale')">
              <USelect
                v-model="editForm.locale"
                :items="localeItems"
                class="w-full"
              />
            </UFormField>
          </div>
          <USwitch
            v-model="editForm.is_active"
            :label="t('users.active')"
          />
          <UFormField
            :label="t('triage.userKind.label')"
            :help="t('triage.userKind.help')"
          >
            <USelect
              v-model="editForm.kind"
              :items="kindItems"
              class="w-60"
              data-testid="user-kind"
            />
          </UFormField>
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

    <UModal
      v-model:open="resetOpen"
      :title="t('users.resetTitle', { username: resetUser?.username ?? '' })"
      :dismissible="!resetting"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField :label="t('account.newPassword')">
            <UInput
              v-model="resetForm.password"
              type="password"
              autocomplete="new-password"
              class="w-full"
            />
          </UFormField>
          <UCheckbox
            v-model="resetForm.must_change_password"
            :label="t('users.resetMustChange')"
          />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="resetting"
            :label="t('common.cancel')"
            @click="resetOpen = false"
          />
          <UButton
            :disabled="!resetValid"
            :loading="resetting"
            :label="t('common.save')"
            @click="doReset"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="deleteOpen"
      :title="t('users.deleteTitle', { username: deleteUser?.username ?? '' })"
      :body="t('users.deleteBody')"
      color="error"
      :confirm-label="t('common.delete')"
      :loading="deleting"
      @confirm="doDelete"
    />
  </PageShell>
</template>
