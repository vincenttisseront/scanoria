<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Sauvegardes d'un module permanent (0.4, chantier A) : liste publiée par le
service système, « Sauvegarder maintenant », et restauration dans une modale
de confirmation irréversible. Chaque action affiche un indicateur d'attente,
puis l'affichage est rafraîchi à la fin de la demande, sans recharger la page.
-->

<script setup lang="ts">
import type { InstalledModule, ModuleBackup } from '~/composables/useCatalog'

const props = defineProps<{
  module: InstalledModule
  name: string
  admin: boolean
  busy?: boolean
}>()
const emit = defineEmits<{ done: [] }>()

const { t, locale } = useI18n()
const fmt = useFormat()
const backupReq = useHelperRequest()
const restoreReq = useHelperRequest()

const backups = computed<ModuleBackup[]>(() => props.module.backups ?? [])
const running = computed(() => backupReq.running.value || restoreReq.running.value)
const disabled = computed(() => running.value || !!props.busy || !['healthy', 'disabled', 'failed'].includes(props.module.status))

function size(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = bytes
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  const n = new Intl.NumberFormat(locale.value, { maximumFractionDigits: i ? 1 : 0 }).format(v)
  return t(`catalog.backups.units.${units[i]}`, { n })
}

function contents(b: ModuleBackup): string {
  const parts: string[] = []
  if (b.database) parts.push(t('catalog.backups.database'))
  if (b.volumes.length) parts.push(t('catalog.backups.volumes', { list: b.volumes.join(', ') }))
  return parts.join(' · ') || t('catalog.backups.empty')
}

async function backupNow() {
  await backupReq.run(`/api/catalog/modules/${encodeURIComponent(props.module.id)}/backup`, {}, { timeoutMs: 60 * 60_000 })
  emit('done')
}

const target = ref<ModuleBackup | null>(null)
const restoreOpen = ref(false)
function askRestore(b: ModuleBackup) {
  target.value = b
  restoreOpen.value = true
}
async function restore() {
  if (!target.value) return
  await restoreReq.run(`/api/catalog/modules/${encodeURIComponent(props.module.id)}/restore`,
    { backup: target.value.id }, { timeoutMs: 60 * 60_000 })
  restoreOpen.value = false
  emit('done')
}
</script>

<template>
  <div
    class="mt-4 rounded border border-default p-3"
    data-backups
  >
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="text-sm font-semibold">
        {{ t('catalog.backups.title') }}
      </h3>
      <UButton
        v-if="admin"
        icon="i-lucide-archive"
        size="sm"
        color="neutral"
        variant="outline"
        :loading="backupReq.running.value"
        :disabled="disabled && !backupReq.running.value"
        :label="t('catalog.backups.now')"
        data-backup-now
        @click="backupNow"
      />
    </div>
    <p class="text-xs text-muted">
      {{ t('catalog.backups.help') }}
    </p>
    <p
      v-if="!backups.length"
      class="mt-2 text-sm text-muted"
    >
      {{ t('catalog.backups.none') }}
    </p>
    <ul
      v-else
      class="mt-2 divide-y divide-default text-sm"
    >
      <li
        v-for="b in backups"
        :key="b.id"
        class="flex flex-wrap items-center justify-between gap-2 py-2"
        data-backup
      >
        <div>
          <p>
            {{ fmt.date(b.created_at) }}
            <UBadge
              color="neutral"
              variant="subtle"
              class="ml-1"
              :label="t(`catalog.backups.reasons.${b.reason}`)"
            />
          </p>
          <p class="text-xs text-muted">
            {{ t('catalog.backups.line', { version: b.module_version, size: size(b.size_bytes), contents: contents(b) }) }}
          </p>
        </div>
        <UButton
          v-if="admin"
          icon="i-lucide-history"
          size="sm"
          color="warning"
          variant="outline"
          :disabled="disabled || b.module_version !== module.version"
          :title="b.module_version !== module.version ? t('catalog.backups.otherVersion', { version: b.module_version }) : undefined"
          :label="t('catalog.backups.restore')"
          @click="askRestore(b)"
        />
      </li>
    </ul>
    <div class="mt-2 space-y-1">
      <RequestProgress
        :active="backupReq.running.value"
        :label="backupReq.label.value"
      />
      <RequestProgress
        :active="restoreReq.running.value"
        :label="restoreReq.label.value"
      />
    </div>

    <ConfirmModal
      v-model:open="restoreOpen"
      :title="t('catalog.backups.restoreTitle', { name })"
      :body="target ? t('catalog.backups.restoreBody', { date: fmt.date(target.created_at), contents: contents(target) }) : ''"
      :ack="t('catalog.backups.restoreAck')"
      :confirm-label="t('catalog.backups.restore')"
      color="error"
      :loading="restoreReq.running.value"
      @confirm="restore"
    >
      <RequestProgress
        :active="restoreReq.running.value"
        :label="restoreReq.label.value"
      />
    </ConfirmModal>
  </div>
</template>
