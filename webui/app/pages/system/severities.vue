<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Normalisation des gravités (G5) : pour chaque module, gravité native →
gravité normalisée. Lignes créées automatiquement au premier résultat ;
un administrateur peut les modifier (audité), avec la valeur d'origine
affichée et un retour à l'origine.
-->

<script setup lang="ts">
import { SEVERITIES, type Severity } from '#shared/analysis'

const { t } = useI18n()
useHead({ title: computed(() => t('findings.severities.title')) })

const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()

interface Row {
  module_id: string
  native: string
  severity: Severity
  origin: Severity
  builtin: boolean
  updated_by: string | null
  updated_at: string
}

const rows = ref<Row[]>([])
const loading = ref(false)
const saving = ref<string | null>(null)
const isAdmin = computed(() => session.can('admin'))

async function load() {
  loading.value = true
  try {
    rows.value = (await api<{ items: Row[] }>('/api/severity-maps')).items
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const modules = computed(() => {
  const out = new Map<string, Row[]>()
  for (const r of rows.value) out.set(r.module_id, [...(out.get(r.module_id) ?? []), r])
  return [...out.entries()]
})
const severityItems = computed(() => SEVERITIES.map(s => ({ label: t(`findings.severity.${s}`), value: s })))
const key = (r: Row) => `${r.module_id}:${r.native}`

async function save(r: Row, severity: Severity | null) {
  saving.value = key(r)
  try {
    const res = await api<{ severity: Severity, builtin: boolean }>('/api/severity-maps', { method: 'PATCH', body: { module_id: r.module_id, native: r.native, severity } })
    toast.add({ title: t('findings.severities.saved'), color: 'success' })
    Object.assign(r, res)
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
    await load()
  }
  finally {
    saving.value = null
  }
}
</script>

<template>
  <PageShell :title="t('findings.severities.title')">
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
      {{ t('findings.severities.help') }}
    </p>
    <UAlert
      v-if="!isAdmin"
      color="neutral"
      variant="subtle"
      icon="i-lucide-lock"
      :title="t('findings.severities.readOnly')"
    />

    <UCard v-if="!modules.length">
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
        v-else
        class="text-sm text-muted"
      >
        {{ t('findings.severities.none') }}
      </p>
    </UCard>

    <UCard
      v-for="[moduleId, list] in modules"
      :key="moduleId"
    >
      <template #header>
        <h2 class="font-mono font-semibold">
          {{ moduleId }}
        </h2>
      </template>
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-muted">
            <th class="py-1 font-normal">
              {{ t('findings.severities.native') }}
            </th>
            <th class="py-1 font-normal">
              {{ t('findings.severities.origin') }}
            </th>
            <th class="py-1 font-normal">
              {{ t('findings.severities.current') }}
            </th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="r in list"
            :key="key(r)"
            class="border-t border-default"
            :data-testid="`map-${key(r)}`"
          >
            <td class="py-2 font-mono text-xs">
              {{ r.native }}
            </td>
            <td class="py-2">
              <FindingsSeverityBadge :severity="r.origin" />
            </td>
            <td class="py-2">
              <div class="flex flex-wrap items-center gap-2">
                <USelect
                  v-if="isAdmin"
                  :model-value="r.severity"
                  :items="severityItems"
                  :loading="saving === key(r)"
                  :disabled="!!saving"
                  class="w-36"
                  @update:model-value="(v: Severity) => v !== r.severity && save(r, v)"
                />
                <FindingsSeverityBadge
                  v-else
                  :severity="r.severity"
                />
                <span
                  v-if="!r.builtin"
                  class="text-xs text-muted"
                >
                  {{ t('findings.severities.modified') }} {{ r.updated_by ? t('findings.severities.by', { user: r.updated_by, date: fmt.date(r.updated_at) }) : '' }}
                </span>
              </div>
            </td>
            <td class="py-2 text-right">
              <UButton
                v-if="isAdmin && !r.builtin"
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-undo-2"
                :label="t('findings.severities.reset')"
                :loading="saving === key(r)"
                @click="save(r, null)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </UCard>
  </PageShell>
</template>
