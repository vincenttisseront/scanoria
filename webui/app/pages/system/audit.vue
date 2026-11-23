<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Journal d'audit : liste paginée et filtrable ; un clic sur une ligne ouvre le
détail dans un panneau latéral (USlideover).
-->

<script setup lang="ts">
import type { TableColumn, TableRow } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'

definePageMeta({ role: 'operator' })

const { t, te } = useI18n()
useHead({ title: computed(() => t('audit.title')) })

const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()

interface AuditRow {
  id: string
  occurred_at: string
  actor_user_id: string | null
  actor_username: string | null
  actor_type: 'user' | 'system' | 'anonymous'
  actor_ip: string | null
  action: string
  target_type: string | null
  target_id: string | null
  outcome: 'success' | 'failure' | 'denied'
  request_id: string | null
  details: Record<string, unknown>
}

const PAGE = 50
const page = ref(1)
const filters = reactive({ action: '', actor: '', outcome: 'all' })
const items = ref<AuditRow[]>([])
const total = ref(0)
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const query: Record<string, unknown> = { limit: PAGE, offset: (page.value - 1) * PAGE }
    const action = filters.action.trim().toLowerCase()
    const actor = filters.actor.trim().toLowerCase()
    if (/^[a-z0-9.-]+$/.test(action)) query.action = action
    if (/^[a-z0-9._-]+$/.test(actor)) query.actor = actor
    if (filters.outcome !== 'all') query.outcome = filters.outcome
    const res = await api<{ items: AuditRow[], total: number }>('/api/audit', { query })
    items.value = res.items
    total.value = res.total
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)
watch(page, load)
let debounce: ReturnType<typeof setTimeout> | undefined
watch(filters, () => {
  clearTimeout(debounce)
  debounce = setTimeout(() => {
    if (page.value !== 1) page.value = 1
    else void load()
  }, 300)
})

const outcomeItems = computed(() => [
  { label: t('audit.allOutcomes'), value: 'all' },
  { label: t('audit.outcomes.success'), value: 'success' },
  { label: t('audit.outcomes.failure'), value: 'failure' },
  { label: t('audit.outcomes.denied'), value: 'denied' },
])

const UBadge = resolveComponent('UBadge')
const outcomeColor = (o: string) => (o === 'success' ? 'success' : o === 'denied' ? 'warning' : 'error')
const actorLabel = (r: AuditRow) => r.actor_username ?? (te(`audit.actorTypes.${r.actor_type}`) ? t(`audit.actorTypes.${r.actor_type}`) : r.actor_type)

const columns = computed<TableColumn<AuditRow>[]>(() => [
  { accessorKey: 'occurred_at', header: t('audit.date'), cell: ({ row }) => fmt.date(row.original.occurred_at) },
  { id: 'actor', header: t('audit.actor'), cell: ({ row }) => actorLabel(row.original) },
  { accessorKey: 'action', header: t('audit.action'), cell: ({ row }) => h('span', { class: 'font-mono text-xs' }, row.original.action) },
  {
    id: 'target',
    header: t('audit.target'),
    cell: ({ row }) => (row.original.target_type ? `${row.original.target_type}:${row.original.target_id ?? ''}` : '—'),
  },
  {
    accessorKey: 'outcome',
    header: t('audit.outcome'),
    cell: ({ row }) => h(UBadge, { color: outcomeColor(row.original.outcome), variant: 'subtle', label: t(`audit.outcomes.${row.original.outcome}`) }),
  },
])

// --- Panneau latéral ---
const selected = ref<AuditRow | null>(null)
const detailOpen = ref(false)
function onSelect(_e: Event, row: TableRow<AuditRow>) {
  selected.value = row.original
  detailOpen.value = true
}
const detailJson = computed(() => JSON.stringify(selected.value?.details ?? {}, null, 2))
</script>

<template>
  <PageShell :title="t('audit.title')">
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

    <div class="flex flex-wrap items-end gap-3">
      <UFormField :label="t('audit.filterAction')">
        <UInput
          v-model="filters.action"
          placeholder="auth."
          icon="i-lucide-search"
        />
      </UFormField>
      <UFormField :label="t('audit.filterActor')">
        <UInput v-model="filters.actor" />
      </UFormField>
      <UFormField :label="t('audit.filterOutcome')">
        <USelect
          v-model="filters.outcome"
          :items="outcomeItems"
          class="w-40"
        />
      </UFormField>
    </div>

    <UCard>
      <p class="mb-2 text-xs text-muted">
        {{ t('audit.total', { total }) }} · {{ t('audit.clickHint') }}
      </p>
      <UTable
        :data="items"
        :columns="columns"
        :loading="loading"
        :empty="t('common.none')"
        class="cursor-pointer"
        @select="onSelect"
      />
      <div
        v-if="total > PAGE"
        class="mt-4 flex justify-end"
      >
        <UPagination
          v-model:page="page"
          :total="total"
          :items-per-page="PAGE"
        />
      </div>
    </UCard>

    <USlideover
      v-model:open="detailOpen"
      :title="t('audit.detailTitle', { id: selected?.id ?? '' })"
      side="right"
    >
      <template #body>
        <dl
          v-if="selected"
          class="space-y-3 text-sm"
        >
          <div>
            <dt class="text-muted">
              {{ t('audit.date') }}
            </dt>
            <dd>{{ fmt.date(selected.occurred_at) }} <span class="font-mono text-xs text-muted">({{ selected.occurred_at }})</span></dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('audit.actor') }}
            </dt>
            <dd>{{ actorLabel(selected) }} · {{ t(`audit.actorTypes.${selected.actor_type}`) }}</dd>
          </div>
          <div v-if="selected.actor_ip">
            <dt class="text-muted">
              {{ t('audit.ip') }}
            </dt>
            <dd class="font-mono">
              {{ selected.actor_ip }}
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('audit.action') }}
            </dt>
            <dd class="font-mono">
              {{ selected.action }}
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('audit.outcome') }}
            </dt>
            <dd>
              <UBadge
                :color="outcomeColor(selected.outcome)"
                variant="subtle"
                :label="t(`audit.outcomes.${selected.outcome}`)"
              />
            </dd>
          </div>
          <div v-if="selected.target_type">
            <dt class="text-muted">
              {{ t('audit.target') }}
            </dt>
            <dd class="font-mono">
              {{ selected.target_type }}:{{ selected.target_id }}
            </dd>
          </div>
          <div v-if="selected.request_id">
            <dt class="text-muted">
              {{ t('audit.requestId') }}
            </dt>
            <dd class="font-mono text-xs">
              {{ selected.request_id }}
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('audit.rawDetails') }}
            </dt>
            <dd>
              <pre class="mt-1 max-h-[50vh] overflow-auto rounded bg-muted p-3 font-mono text-xs">{{ detailJson }}</pre>
            </dd>
          </div>
        </dl>
      </template>
    </USlideover>
  </PageShell>
</template>
