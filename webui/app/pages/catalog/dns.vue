<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

État DNS de l'accès par nom (§ 3.4) : enregistrements à créer (nom de
l'appliance et *.nom), résultat du dernier contrôle par nom et bouton
« vérifier maintenant ».
-->

<script setup lang="ts">
import type { DnsStatus } from '~/composables/useCatalog'

interface DnsView {
  fqdn: string | null
  status: DnsStatus | null
  required: { name: string, type: string, value: string }[]
}

const { t } = useI18n()
useHead({ title: computed(() => t('catalog.dns.title')) })
const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const { api, errorMessage } = useApi()

const view = ref<DnsView | null>(null)
const loadError = ref('')
async function load() {
  try {
    view.value = await api<DnsView>('/api/dns')
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
}
onMounted(load)

const checkReq = useHelperRequest()
async function checkNow() {
  await checkReq.run('/api/dns/check', {})
  await load()
}

const allOk = computed(() => !!view.value?.status?.records.length && view.value.status.records.every(r => r.ok))
</script>

<template>
  <PageShell :title="t('catalog.dns.title')">
    <template #actions>
      <UButton
        to="/catalog"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('catalog.title')"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!view"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="view">
      <UAlert
        v-if="!view.fqdn"
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        :title="t('catalog.dns.noName')"
      />

      <UCard v-if="view.fqdn">
        <template #header>
          <h2 class="font-semibold">
            {{ t('catalog.dns.toCreate') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('catalog.dns.toCreateHelp', { fqdn: view.fqdn }) }}
          </p>
        </template>
        <table
          v-if="view.required.length"
          class="w-full text-sm"
        >
          <thead>
            <tr class="text-left text-muted">
              <th class="py-1">
                {{ t('catalog.dns.name') }}
              </th>
              <th>{{ t('catalog.dns.type') }}</th>
              <th>{{ t('catalog.dns.value') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in view.required"
              :key="`${r.name}-${r.type}`"
            >
              <td class="py-1 font-mono">
                {{ r.name }}
              </td>
              <td>{{ r.type }}</td>
              <td class="font-mono">
                {{ r.value }}
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else
          class="text-sm text-muted"
        >
          {{ t('catalog.dns.toCreateGeneric', { fqdn: view.fqdn }) }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 class="font-semibold">
                {{ t('catalog.dns.lastCheck') }}
              </h2>
              <p class="text-sm text-muted">
                {{ view.status?.checked_at ? fmt.date(view.status.checked_at) : t('catalog.dns.neverChecked') }}
                <template v-if="view.status?.records.length">
                  · {{ allOk ? t('catalog.dns.allOk') : t('catalog.dns.someKo') }}
                </template>
              </p>
            </div>
            <UButton
              v-if="isAdmin"
              icon="i-lucide-radar"
              :loading="checkReq.running.value"
              :disabled="!view.fqdn"
              :label="t('catalog.dns.checkNow')"
              @click="checkNow"
            />
          </div>
        </template>
        <RequestProgress
          :active="checkReq.running.value"
          :label="checkReq.label.value"
        />
        <table
          v-if="view.status?.records.length"
          class="w-full text-sm"
        >
          <thead>
            <tr class="text-left text-muted">
              <th class="py-1">
                {{ t('catalog.dns.name') }}
              </th>
              <th>{{ t('catalog.dns.type') }}</th>
              <th>{{ t('catalog.dns.expected') }}</th>
              <th>{{ t('catalog.dns.resolved') }}</th>
              <th>{{ t('catalog.list.status') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in view.status.records"
              :key="`${r.name}-${r.type}`"
              :data-dns="r.name"
            >
              <td class="py-1 font-mono">
                {{ r.name }}
              </td>
              <td>{{ r.type }}</td>
              <td class="font-mono">
                {{ r.expected }}
              </td>
              <td class="font-mono">
                {{ r.resolved.length ? r.resolved.join(', ') : t('catalog.dns.noAnswer') }}
              </td>
              <td>
                <UBadge
                  :color="r.ok ? 'success' : 'error'"
                  variant="subtle"
                  :label="r.ok ? t('catalog.dns.resolves') : t('catalog.dns.notResolving')"
                />
              </td>
            </tr>
          </tbody>
        </table>
        <p
          v-else-if="view.status"
          class="text-sm text-muted"
        >
          {{ t('catalog.dns.noRecords') }}
        </p>
        <p class="mt-3 text-xs text-muted">
          {{ t('catalog.dns.autoHelp') }}
        </p>
      </UCard>
    </template>
  </PageShell>
</template>
