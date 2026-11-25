<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Profils d'un projet par déclencheur (G9) : PR, nuit, release, sinon le profil
par défaut ; profil demandé par .scanoria.yml (J8) et état de la dernière
lecture du fichier ; « aucun envoi à l'IA » imposé par un verrou (G8).
Un opérateur ne peut pas choisir un profil plus souple : le serveur le refuse.
-->

<script setup lang="ts">
import type { ProfileLocks } from '#shared/analysis'

const props = defineProps<{ projectId: string, canEdit: boolean }>()
const emit = defineEmits<{ changed: [] }>()
const aiLocked = defineModel<boolean>('aiLocked', { default: false })
const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()

interface SlotView { profile_id: string | null, effective_id: string, slug: string, chain: string[], locks: ProfileLocks, from_config: string | null }
interface ConfigState {
  status: 'ok' | 'absent' | 'invalid' | 'unavailable'
  read_at: string
  read_key: string
  sha256: string | null
  issues: { path: string, message: string }[]
  config_key: string | null
  requests: { created: number, skipped: number } | null
}
interface View { slots: Record<ProfileSlot, SlotView>, ai_opt_out: boolean, ai_opt_out_locked: boolean, config_state: ConfigState | null }

const view = ref<View | null>(null)
const profiles = ref<ProfileRow[]>([])
const loadError = ref('')
const form = reactive<Record<ProfileSlot, string>>({ default: '', pr: '', nightly: '', release: '' })
const INHERIT = '__inherit__'

async function load() {
  try {
    const [v, p] = await Promise.all([
      api<View>(`/api/projects/${props.projectId}/profiles`),
      api<{ items: ProfileRow[] }>('/api/profiles'),
    ])
    view.value = v
    profiles.value = p.items
    for (const s of PROFILE_SLOTS) form[s] = v.slots[s].profile_id ?? INHERIT
    aiLocked.value = v.ai_opt_out_locked
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
}
onMounted(load)
watch(() => props.projectId, load)

const items = (slot: ProfileSlot) => [
  ...(slot === 'default' ? [] : [{ label: t('profiles.project.inherit'), value: INHERIT }]),
  ...profiles.value.map(p => ({ label: p.slug, value: p.id })),
]
const dirty = computed(() => !!view.value && PROFILE_SLOTS.some(s => (view.value!.slots[s].profile_id ?? INHERIT) !== form[s]))

const saving = ref(false)
async function save() {
  if (!view.value) return
  saving.value = true
  try {
    const body: Record<string, string | null> = {}
    for (const s of PROFILE_SLOTS) {
      if ((view.value.slots[s].profile_id ?? INHERIT) !== form[s]) body[s] = form[s] === INHERIT ? null : form[s]
    }
    view.value = await api<View>(`/api/projects/${props.projectId}/profiles`, { method: 'PUT', body })
    for (const s of PROFILE_SLOTS) form[s] = view.value.slots[s].profile_id ?? INHERIT
    aiLocked.value = view.value.ai_opt_out_locked
    toast.add({ title: t('profiles.project.saved'), color: 'success' })
    emit('changed')
  }
  catch (err) {
    const { code } = profileErrorDetails(err)
    toast.add({ title: code && te(`profiles.errors.${code}`) ? t(`profiles.errors.${code}`) : errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

const config = computed(() => view.value?.config_state ?? null)
const statusColor = computed(() => ({ ok: 'success', absent: 'neutral', invalid: 'error', unavailable: 'warning' } as const)[config.value?.status ?? 'absent'])
const lockCount = (l: ProfileLocks) => l.required_categories.length + l.required_modules.length + Object.keys(l.gate_floor).length + (l.ai_opt_out ? 1 : 0)
</script>

<template>
  <UCard>
    <template #header>
      <h2 class="font-semibold">
        {{ t('profiles.project.title') }}
      </h2>
      <p class="text-sm text-muted">
        {{ t('profiles.project.help') }}
      </p>
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
    <div
      v-else
      class="space-y-4"
    >
      <div class="grid gap-4 sm:grid-cols-2">
        <UFormField
          v-for="s in PROFILE_SLOTS"
          :key="s"
          :label="t(`profiles.slots.${s}`)"
          :help="t(`profiles.project.slotHelp.${s}`)"
        >
          <USelect
            v-model="form[s]"
            :items="items(s)"
            class="w-full"
            :disabled="!canEdit"
            :data-testid="`slot-${s}`"
          />
          <p class="mt-1 flex flex-wrap items-center gap-1 text-xs text-muted">
            <span>{{ t('profiles.project.effective') }} <span class="font-mono">{{ view.slots[s].chain.join(' › ') }}</span></span>
            <UBadge
              v-if="lockCount(view.slots[s].locks)"
              color="neutral"
              variant="subtle"
              size="sm"
              icon="i-lucide-lock"
              :label="t('profiles.project.locks', { n: lockCount(view.slots[s].locks) })"
            />
            <UBadge
              v-if="view.slots[s].from_config"
              color="info"
              variant="subtle"
              size="sm"
              icon="i-lucide-file-code"
              :label="t('profiles.project.fromConfig', { slug: view.slots[s].from_config })"
            />
          </p>
        </UFormField>
      </div>
      <div
        v-if="canEdit"
        class="flex justify-end"
      >
        <UButton
          :loading="saving"
          :disabled="!dirty"
          :label="t('common.save')"
          data-testid="slots-save"
          @click="save"
        />
      </div>

      <UAlert
        v-if="view.ai_opt_out_locked"
        color="neutral"
        variant="subtle"
        icon="i-lucide-lock"
        :title="t('profiles.project.aiLocked')"
        data-testid="ai-locked"
      />

      <div class="border-t border-default pt-4">
        <h3 class="flex items-center gap-2 text-sm font-medium">
          {{ t('profiles.config.title') }}
          <UBadge
            :color="statusColor"
            variant="subtle"
            size="sm"
            :label="t(`profiles.config.status.${config?.status ?? 'absent'}`)"
            data-testid="config-status"
          />
        </h3>
        <p class="text-sm text-muted">
          {{ t('profiles.config.help') }}
          <ULink
            to="/api/config/schema"
            target="_blank"
          >
            {{ t('profiles.config.schema') }}
          </ULink>
        </p>
        <dl
          v-if="config"
          class="mt-2 grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[12rem_1fr]"
        >
          <dt class="text-muted">
            {{ t('profiles.config.readAt') }}
          </dt>
          <dd>{{ fmt.date(config.read_at) }} · <span class="font-mono text-xs">{{ config.read_key.slice(0, 12) }}</span></dd>
          <template v-if="config.status !== 'ok' && config.config_key">
            <dt class="text-muted">
              {{ t('profiles.config.applied') }}
            </dt>
            <dd class="font-mono text-xs">
              {{ config.config_key.slice(0, 12) }}
            </dd>
          </template>
          <template v-if="config.requests">
            <dt class="text-muted">
              {{ t('profiles.config.requests') }}
            </dt>
            <dd>
              {{ t('profiles.config.requestsCount', { created: config.requests.created, skipped: config.requests.skipped }) }}
              <ULink :to="`/findings/exceptions?project_id=${projectId}`">
                {{ t('profiles.config.review') }}
              </ULink>
            </dd>
          </template>
        </dl>
        <ul
          v-if="config?.issues.length"
          class="mt-2 list-disc ps-5 text-sm"
          :class="config.status === 'invalid' ? 'text-error' : 'text-warning'"
        >
          <li
            v-for="(i, n) in config.issues"
            :key="n"
          >
            <span
              v-if="i.path"
              class="font-mono"
            >{{ i.path }}</span> {{ i.message }}
          </li>
        </ul>
      </div>
    </div>
  </UCard>
</template>
