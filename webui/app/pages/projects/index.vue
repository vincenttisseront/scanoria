<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Projets (§ 6.1) : dépôts découverts dans les forges ou ajoutés à la main,
avec leur source, leur planification et ce que la détection a trouvé.
-->

<script setup lang="ts">
import type { Project } from '~/composables/useProjects'

const { t } = useI18n()
useHead({ title: computed(() => t('projects.title')) })
const session = useSession()
const fmt = useFormat()
const { api, message, label, sourceLabel } = useProjects()

const archived = ref(false)
const items = ref<Project[] | null>(null)
const loadError = ref('')
const filter = ref('')

async function load() {
  loadError.value = ''
  try {
    items.value = (await api<{ items: Project[] }>('/api/projects', { query: archived.value ? { archived: '1' } : {} })).items
  }
  catch (err) {
    loadError.value = message(err)
  }
}
onMounted(load)
watch(archived, () => {
  items.value = null
  void load()
})

const shown = computed(() => {
  const q = filter.value.trim().toLowerCase()
  const list = items.value ?? []
  return q ? list.filter(p => `${p.name} ${p.slug} ${p.repo_full_name ?? ''} ${p.repo_url ?? ''}`.toLowerCase().includes(q)) : list
})

function languages(p: Project): string {
  return p.detection?.languages?.slice(0, 4).join(', ') || '—'
}
</script>

<template>
  <PageShell :title="t('projects.title')">
    <template #actions>
      <UButton
        to="/projects/forges"
        icon="i-lucide-git-branch"
        color="neutral"
        variant="ghost"
        :label="t('projects.forges.title')"
      />
      <UButton
        v-if="session.can('operator')"
        to="/projects/new"
        icon="i-lucide-plus"
        :label="t('projects.add')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('projects.help') }}
    </p>

    <div class="flex flex-wrap items-center gap-3">
      <UInput
        v-model="filter"
        icon="i-lucide-search"
        :placeholder="t('projects.filter')"
        class="w-72"
      />
      <USwitch
        v-model="archived"
        :label="t('projects.showArchived')"
      />
    </div>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!items"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <UCard v-else-if="!shown.length">
      <p class="text-sm text-muted">
        {{ archived ? t('projects.emptyArchived') : t('projects.empty') }}
      </p>
    </UCard>
    <div
      v-else
      class="overflow-x-auto"
    >
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-muted">
            <th class="py-2">
              {{ t('projects.name') }}
            </th>
            <th>{{ t('projects.sourceTitle') }}</th>
            <th>{{ t('projects.languages') }}</th>
            <th>{{ t('projects.scheduleTitle') }}</th>
            <th>{{ t('projects.lastScan') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="p in shown"
            :key="p.id"
            class="border-t border-default"
          >
            <td class="py-2">
              <NuxtLink
                :to="`/projects/${p.id}`"
                class="font-medium text-primary hover:underline"
              >
                {{ p.name }}
              </NuxtLink>
              <UBadge
                v-if="p.ai_opt_out"
                color="neutral"
                variant="subtle"
                size="sm"
                class="ml-2"
                :label="t('projects.aiOptOutShort')"
              />
            </td>
            <td class="font-mono text-xs">
              {{ sourceLabel(p) }}
            </td>
            <td>{{ languages(p) }}</td>
            <td>{{ label('schedule', p.schedule) }}</td>
            <td>
              <template v-if="p.last_scan">
                #{{ p.last_scan.number }} · {{ p.last_scan.verdict ?? p.last_scan.status }} · {{ fmt.date(p.last_scan.queued_at) }}
              </template>
              <span
                v-else
                class="text-muted"
              >{{ t('projects.noScan') }}</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </PageShell>
</template>
