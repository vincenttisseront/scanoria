<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Versions de modules figées par le projet (G6) : reproductibilité et audit.
Seul un administrateur fige ou libère une version, avec un motif ; la
console avertit quand la version figée est retirée du catalogue, vulnérable
ou absente de la machine (analyse alors non concluante, erreur d'infrastructure).
-->

<script setup lang="ts">
import { reasonOf } from '~/utils/vigilance'

const props = defineProps<{ projectId: string, isAdmin: boolean }>()

interface PinRow {
  module_id: string
  version: string
  reason: string
  pinned_at: string
  installed_version: string | null
  warnings: ('retired' | 'vulnerable' | 'missing')[]
}

const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const fmt = useFormat()
const toast = useToast()
const pins = ref<PinRow[]>([])
const pinnable = ref<{ id: string, version: string }[]>([])
const loaded = ref(false)
const saving = ref(false)

const url = computed(() => `/api/projects/${encodeURIComponent(props.projectId)}/pins`)
async function load() {
  try {
    const r = await api<{ pins: PinRow[], pinnable: { id: string, version: string }[] }>(url.value)
    pins.value = r.pins
    pinnable.value = r.pinnable
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loaded.value = true
  }
}
onMounted(load)

function failure(err: unknown) {
  const r = reasonOf(err)
  toast.add({ title: r && te(`vigilance.reasons.${r}`) ? t(`vigilance.reasons.${r}`) : errorMessage(err), color: 'error' })
}

const pinOpen = ref(false)
const moduleId = ref<string | undefined>(undefined)
const reason = ref('')
const items = computed(() => pinnable.value.map(m => ({ value: m.id, label: `${m.id} ${m.version}` })))
function openPin() {
  moduleId.value = pinnable.value[0]?.id
  reason.value = ''
  pinOpen.value = true
}
async function pin() {
  if (!moduleId.value || reason.value.trim().length < 3) return
  saving.value = true
  try {
    await api(`${url.value}/${encodeURIComponent(moduleId.value)}`, { method: 'PUT', body: { reason: reason.value.trim() } })
    pinOpen.value = false
    toast.add({ title: t('vigilance.pins.pinned'), color: 'success' })
    await load()
  }
  catch (err) {
    failure(err)
  }
  finally {
    saving.value = false
  }
}

const unpinTarget = ref<PinRow | null>(null)
const unpinOpen = computed({
  get: () => !!unpinTarget.value,
  set: (v: boolean) => {
    if (!v) unpinTarget.value = null
  },
})
async function unpin() {
  const p = unpinTarget.value
  if (!p) return
  saving.value = true
  try {
    await api(`${url.value}/${encodeURIComponent(p.module_id)}`, { method: 'DELETE' })
    unpinTarget.value = null
    toast.add({ title: t('vigilance.pins.unpinned'), color: 'success' })
    await load()
  }
  catch (err) {
    failure(err)
  }
  finally {
    saving.value = false
  }
}
</script>

<template>
  <UCard data-testid="project-pins">
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="font-semibold">
            {{ t('vigilance.pins.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('vigilance.pins.help') }}
          </p>
        </div>
        <UButton
          v-if="isAdmin && pinnable.length"
          icon="i-lucide-pin"
          size="sm"
          color="neutral"
          variant="subtle"
          :label="t('vigilance.pins.add')"
          @click="openPin"
        />
      </div>
    </template>

    <div
      v-if="!loaded"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <p
      v-else-if="!pins.length"
      class="text-sm text-muted"
    >
      {{ t('vigilance.pins.none') }}
    </p>
    <ul
      v-else
      class="space-y-2 text-sm"
    >
      <li
        v-for="p in pins"
        :key="p.module_id"
        class="flex flex-wrap items-center gap-2"
      >
        <UIcon
          name="i-lucide-pin"
          class="size-4"
        />
        <span class="font-medium">{{ p.module_id }} {{ p.version }}</span>
        <span class="text-muted">{{ t('vigilance.pins.since', { date: fmt.date(p.pinned_at), installed: p.installed_version ?? '—' }) }}</span>
        <span class="text-muted">« {{ p.reason }} »</span>
        <UBadge
          v-for="w in p.warnings"
          :key="w"
          :color="w === 'retired' ? 'warning' : 'error'"
          variant="subtle"
          :label="t(`vigilance.pins.warning.${w}`)"
        />
        <UButton
          v-if="isAdmin"
          size="xs"
          color="neutral"
          variant="ghost"
          icon="i-lucide-pin-off"
          :label="t('vigilance.pins.unpin')"
          @click="unpinTarget = p"
        />
      </li>
    </ul>

    <ConfirmModal
      v-model:open="pinOpen"
      :title="t('vigilance.pins.addTitle')"
      :body="t('vigilance.pins.addBody')"
      :confirm-label="t('vigilance.pins.add')"
      :loading="saving"
      @confirm="pin"
    >
      <UFormField :label="t('vigilance.pins.module')">
        <USelect
          v-model="moduleId"
          :items="items"
          class="w-full"
        />
      </UFormField>
      <UFormField
        :label="t('vigilance.pins.reason')"
        required
      >
        <UTextarea
          v-model="reason"
          class="w-full"
          :rows="2"
        />
      </UFormField>
    </ConfirmModal>
    <ConfirmModal
      v-model:open="unpinOpen"
      color="warning"
      :title="t('vigilance.pins.unpinTitle', { module: unpinTarget?.module_id ?? '' })"
      :body="t('vigilance.pins.unpinBody')"
      :confirm-label="t('vigilance.pins.unpin')"
      :loading="saving"
      @confirm="unpin"
    />
  </UCard>
</template>
