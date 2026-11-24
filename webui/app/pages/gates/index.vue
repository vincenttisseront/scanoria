<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Quality gates : liste, création par copie (administrateur).
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'
import { SLUG_RE, type GateRules } from '#shared/analysis'

const { t, te } = useI18n()
useHead({ title: computed(() => t('gates.title')) })

const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface GateRow {
  id: string
  slug: string
  builtin: boolean
  rules: GateRules
  updated_at: string
  updated_by_username: string | null
  projects: number
}

function message(err: unknown): string {
  const code = gateErrorCode(err)
  return code && te(`gates.errors.${code}`) ? t(`gates.errors.${code}`) : errorMessage(err)
}

const gates = ref<GateRow[]>([])
const loading = ref(false)
async function load() {
  loading.value = true
  try {
    gates.value = (await api<{ items: GateRow[] }>('/api/gates')).items
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const UBadge = resolveComponent('UBadge')
const ULink = resolveComponent('ULink')
const columns = computed<TableColumn<GateRow>[]>(() => [
  {
    accessorKey: 'slug',
    header: t('gates.slug'),
    cell: ({ row }) => h('div', { class: 'flex items-center gap-2' }, [
      h(ULink, { to: `/gates/${row.original.id}`, class: 'font-medium' }, () => row.original.slug),
      row.original.builtin ? h(UBadge, { color: 'neutral', variant: 'subtle', size: 'sm', label: t('gates.builtin') }) : null,
    ]),
  },
  { accessorKey: 'projects', header: t('gates.projects') },
  {
    accessorKey: 'updated_at',
    header: t('gates.updated'),
    cell: ({ row }) => row.original.updated_by_username
      ? `${fmt.date(row.original.updated_at)} ${t('gates.by', { user: row.original.updated_by_username })}`
      : fmt.date(row.original.updated_at),
  },
])

const createOpen = ref(false)
const creating = ref(false)
const form = reactive({ slug: '', copy_from: '' })
const copyItems = computed(() => gates.value.map(g => ({ label: g.slug, value: g.id })))
const valid = computed(() => SLUG_RE.test(form.slug))
function openCreate() {
  form.slug = ''
  form.copy_from = gates.value.find(g => g.builtin)?.id ?? gates.value[0]?.id ?? ''
  createOpen.value = true
}
async function create() {
  creating.value = true
  try {
    const gate = await api<GateRow>('/api/gates', { method: 'POST', body: { slug: form.slug, ...(form.copy_from ? { copy_from: form.copy_from } : {}) } })
    toast.add({ title: t('gates.created'), color: 'success' })
    createOpen.value = false
    await navigateTo(`/gates/${gate.id}`)
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
  <PageShell :title="t('gates.title')">
    <template #actions>
      <UButton
        v-if="session.can('admin')"
        icon="i-lucide-plus"
        :label="t('gates.create')"
        data-testid="gate-create"
        @click="openCreate"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('gates.intro') }}
    </p>

    <UTable
      :data="gates"
      :columns="columns"
      :loading="loading"
      :empty="t('gates.empty')"
    />

    <UModal
      v-model:open="createOpen"
      :title="t('gates.createTitle')"
      :dismissible="!creating"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField
            :label="t('gates.slug')"
            :help="t('gates.slugHelp')"
          >
            <UInput
              v-model="form.slug"
              data-testid="gate-slug"
              autocomplete="off"
            />
          </UFormField>
          <UFormField :label="t('gates.copyFrom')">
            <USelect
              v-model="form.copy_from"
              :items="copyItems"
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
            data-testid="gate-create-confirm"
            @click="create"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
