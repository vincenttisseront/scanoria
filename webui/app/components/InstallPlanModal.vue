<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Modale d'installation (un module, une sélection ou un pack) : le plan calculé
par la console est affiché avant toute demande — modules ajoutés
automatiquement et pourquoi, ressources, réglages noyau, DNS, licences à
accepter explicitement — puis installation en une confirmation.
-->

<script setup lang="ts">
import type { InstallPlan } from '~/composables/useCatalog'

const props = defineProps<{
  title: string
  request: { modules: { id: string, version?: string, options?: Record<string, unknown> }[] } | { pack: string } | null
}>()
const emit = defineEmits<{ done: [status: string | null] }>()
const open = defineModel<boolean>('open', { default: false })

const { t } = useI18n()
const { api, errorMessage } = useApi()
const text = useModuleText()
const req = useHelperRequest()

const plan = ref<InstallPlan | null>(null)
const loading = ref(false)
const loadError = ref('')
const accepted = ref<string[]>([])

watch(open, async (value) => {
  if (!value || !props.request) return
  plan.value = null
  loadError.value = ''
  accepted.value = []
  loading.value = true
  try {
    plan.value = await api<InstallPlan>('/api/catalog/plan', { method: 'POST', body: props.request })
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
})

/** Blocages hors licences : la case à cocher lève ce dernier. */
const blockers = computed(() => plan.value?.blockers.filter(b => b.code !== 'E_LICENSE_REQUIRED') ?? [])
const licenseItems = computed(() => plan.value?.items.filter(i => i.needs_acceptance) ?? [])
const allAccepted = computed(() => licenseItems.value.every(i => accepted.value.includes(i.id)))
const canInstall = computed(() => !!plan.value && plan.value.items.length > 0 && !blockers.value.length && allAccepted.value)
const autoAdded = computed(() => plan.value?.items.filter(i => i.reason !== 'requested') ?? [])

function toggle(id: string, value: boolean | 'indeterminate') {
  accepted.value = value === true ? [...new Set([...accepted.value, id])] : accepted.value.filter(x => x !== id)
}

async function install() {
  if (!props.request || !canInstall.value) return
  const r = await req.run('/api/catalog/install', { ...props.request, accept_licenses: accepted.value }, { timeoutMs: 60 * 60_000 })
  open.value = false
  emit('done', r?.status ?? null)
}
</script>

<template>
  <UModal
    v-model:open="open"
    :title="title"
    :dismissible="!req.running.value"
    :ui="{ content: 'max-w-2xl' }"
  >
    <template #body>
      <div
        v-if="loading"
        class="flex items-center gap-2 text-sm text-muted"
        role="status"
      >
        <UIcon
          name="i-lucide-loader-circle"
          class="size-4 animate-spin"
        />
        {{ t('catalog.plan.computing') }}
      </div>
      <UAlert
        v-else-if="loadError"
        color="error"
        variant="subtle"
        :title="loadError"
      />
      <div
        v-else-if="plan"
        class="space-y-4"
      >
        <div>
          <h3 class="mb-2 text-sm font-semibold">
            {{ t('catalog.plan.modules', { count: plan.items.length }) }}
          </h3>
          <ul class="divide-y divide-default rounded border border-default">
            <li
              v-for="item in plan.items"
              :key="item.id"
              class="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
              :data-plan-item="item.id"
            >
              <span>
                <span class="font-medium">{{ item.name }}</span>
                <span class="text-muted"> {{ item.version }} · {{ text.typeLabel(item.type) }} · {{ item.license.spdx }}</span>
              </span>
              <UBadge
                :color="item.reason === 'requested' ? 'neutral' : 'info'"
                variant="subtle"
                :label="text.reasonText(item)"
              />
            </li>
          </ul>
          <p
            v-if="autoAdded.length"
            class="mt-2 text-sm text-muted"
          >
            {{ t('catalog.plan.autoAddedHelp') }}
          </p>
          <p
            v-if="plan.skipped.length"
            class="mt-2 text-sm text-muted"
          >
            {{ t('catalog.plan.skipped', { list: plan.skipped.join(', ') }) }}
          </p>
        </div>

        <div>
          <h3 class="mb-2 text-sm font-semibold">
            {{ t('catalog.plan.resources') }}
          </h3>
          <ul class="space-y-1 text-sm">
            <li
              v-for="c in plan.checks"
              :key="c.kind"
              class="flex items-center gap-2"
            >
              <UIcon
                :name="c.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
                :class="c.ok ? 'text-success' : 'text-error'"
              />
              {{ text.checkText(c) }}
            </li>
          </ul>
        </div>

        <p
          v-for="s in plan.sysctl"
          :key="`${s.module}-${s.key}`"
          class="text-sm text-muted"
        >
          {{ t('catalog.plan.sysctl', { module: s.module, key: s.key, value: String(s.value) }) }}
        </p>

        <UAlert
          v-for="(w, i) in plan.warnings"
          :key="`w${i}`"
          color="warning"
          variant="subtle"
          icon="i-lucide-triangle-alert"
          :title="text.issueText(w)"
        />
        <UAlert
          v-for="(b, i) in blockers"
          :key="`b${i}`"
          color="error"
          variant="subtle"
          icon="i-lucide-octagon-x"
          :title="text.issueText(b)"
        />

        <div
          v-if="licenseItems.length"
          class="space-y-2 rounded border border-warning p-3"
        >
          <h3 class="text-sm font-semibold">
            {{ t('catalog.plan.licensesTitle') }}
          </h3>
          <div
            v-for="item in licenseItems"
            :key="item.id"
            class="space-y-1"
          >
            <p class="text-sm">
              {{ t('catalog.plan.licenseLine', { name: item.name, spdx: item.license.spdx, restriction: text.restrictionLabel(item.license.restrictions) }) }}
            </p>
            <p
              v-if="item.license.note"
              class="text-sm text-muted"
            >
              {{ item.license.note }}
            </p>
            <UCheckbox
              :model-value="accepted.includes(item.id)"
              :label="t('catalog.plan.accept', { name: item.name })"
              :data-accept="item.id"
              @update:model-value="v => toggle(item.id, v)"
            />
          </div>
        </div>

        <RequestProgress
          :active="req.running.value"
          :label="req.label.value"
        />
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton
          color="neutral"
          variant="ghost"
          :disabled="req.running.value"
          :label="t('common.cancel')"
          @click="open = false"
        />
        <UButton
          icon="i-lucide-download"
          :loading="req.running.value"
          :disabled="!canInstall"
          :label="t('catalog.plan.install', { count: plan?.items.length ?? 0 })"
          @click="install"
        />
      </div>
    </template>
  </UModal>
</template>
