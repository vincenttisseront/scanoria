<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Intégration CI d'un projet : gate affecté, jetons d'API (valeur montrée une
seule fois), badge du verdict, client scanoria-scan et exemple d'étape de CI.
La page projet (chantier A) y renvoie.
-->

<script setup lang="ts">
import type { TableColumn } from '@nuxt/ui'
import { h, resolveComponent } from 'vue'

const { t, te } = useI18n()
const route = useRoute()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface CiInfo {
  project: { id: string, slug: string, name: string, archived: boolean, default_branch: string | null }
  gate: { id: string, slug: string, builtin: boolean } | null
  badge: { enabled: boolean, path: string }
  active_tokens: number
}
interface TokenRow {
  id: string
  name: string
  prefix: string
  created_at: string
  created_by_username: string | null
  expires_at: string | null
  last_used_at: string | null
  revoked_at: string | null
}

const id = computed(() => String(route.params.id))
const info = ref<CiInfo | null>(null)
const tokens = ref<TokenRow[]>([])
const loading = ref(false)
const isOperator = computed(() => session.can('operator'))

useHead({ title: computed(() => info.value ? `${t('gates.ci.title')} · ${info.value.project.name}` : t('gates.ci.title')) })

function message(err: unknown): string {
  const code = gateErrorCode(err)
  return code && te(`gates.errors.${code}`) ? t(`gates.errors.${code}`) : errorMessage(err)
}

const loadError = ref('')
async function load() {
  loading.value = true
  try {
    info.value = await api<CiInfo>(`/api/gates/projects/${id.value}`)
    if (isOperator.value) tokens.value = (await api<{ items: TokenRow[] }>(`/api/projects/${id.value}/tokens`)).items
    loadError.value = ''
  }
  catch (err) {
    loadError.value = message(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

const origin = computed(() => (import.meta.client ? window.location.origin : ''))

function tokenState(row: TokenRow): 'active' | 'revoked' | 'expired' {
  if (row.revoked_at) return 'revoked'
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) return 'expired'
  return 'active'
}

const UBadge = resolveComponent('UBadge')
const UButton = resolveComponent('UButton')
const columns = computed<TableColumn<TokenRow>[]>(() => [
  { accessorKey: 'name', header: t('gates.ci.name') },
  { accessorKey: 'prefix', header: t('gates.ci.prefix'), cell: ({ row }) => h('code', `${row.original.prefix}…`) },
  { accessorKey: 'created_at', header: t('gates.ci.created'), cell: ({ row }) => fmt.date(row.original.created_at) },
  { accessorKey: 'expires_at', header: t('gates.ci.expires'), cell: ({ row }) => row.original.expires_at ? fmt.date(row.original.expires_at) : t('gates.ci.noExpiry') },
  { accessorKey: 'last_used_at', header: t('gates.ci.lastUsed'), cell: ({ row }) => fmt.date(row.original.last_used_at) },
  {
    id: 'state',
    header: t('gates.ci.state'),
    cell: ({ row }) => {
      const s = tokenState(row.original)
      return h(UBadge, { color: s === 'active' ? 'success' : 'neutral', variant: 'subtle', size: 'sm', label: t(`gates.ci.${s}`) })
    },
  },
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => tokenState(row.original) === 'revoked'
      ? null
      : h(UButton, { size: 'xs', color: 'error', variant: 'ghost', label: t('gates.ci.revoke'), onClick: () => askRevoke(row.original) }),
  },
])

// --- Création d'un jeton ---
const createOpen = ref(false)
const creating = ref(false)
const form = reactive({ name: '', expires: null as number | null })
const created = ref<string | null>(null)
function openCreate() {
  form.name = 'ci'
  form.expires = null
  created.value = null
  createOpen.value = true
}
async function createToken() {
  creating.value = true
  try {
    const res = await api<TokenRow & { value: string }>(`/api/projects/${id.value}/tokens`, {
      method: 'POST',
      body: { name: form.name.trim(), expires_in_days: form.expires || null },
    })
    created.value = res.value
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    creating.value = false
  }
}
function closeCreate() {
  created.value = null
  createOpen.value = false
}
watch(createOpen, (open) => {
  if (!open) created.value = null
})
async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    toast.add({ title: t('gates.ci.copied'), color: 'success' })
  }
  catch {
    // presse-papiers indisponible : la valeur reste sélectionnable
  }
}

// --- Révocation ---
const revokeOpen = ref(false)
const revoking = ref(false)
const target = ref<TokenRow | null>(null)
function askRevoke(row: TokenRow) {
  target.value = row
  revokeOpen.value = true
}
async function revoke() {
  if (!target.value) return
  revoking.value = true
  try {
    await api(`/api/projects/${id.value}/tokens/${target.value.id}`, { method: 'DELETE' })
    toast.add({ title: t('gates.ci.revoked_ok'), color: 'success' })
    revokeOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    revoking.value = false
  }
}

// --- Badge ---
const badgeSaving = ref(false)
async function setBadge(enabled: boolean) {
  badgeSaving.value = true
  try {
    await api(`/api/badges/projects/${id.value}`, { method: 'PUT', body: { enabled } })
    toast.add({ title: enabled ? t('gates.ci.badgeOn') : t('gates.ci.badgeOff'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    badgeSaving.value = false
  }
}

const example = computed(() => {
  const p = info.value?.project
  if (!p) return ''
  return [
    '- name: Scanoria',
    '  env:',
    '    SCANORIA_TOKEN: ${{ secrets.SCANORIA_TOKEN }}',
    '  run: |',
    `    curl -fsSo scanoria-scan ${origin.value}/api/gates/client`,
    `    sh scanoria-scan --url ${origin.value} --project ${p.id} --ref "$GITHUB_REF_NAME" --wait`,
  ].join('\n')
})
</script>

<template>
  <PageShell :title="info ? `${t('gates.ci.title')} · ${info.project.name}` : t('gates.ci.title')">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <p class="text-sm text-muted">
      {{ t('gates.ci.intro') }}
    </p>

    <div
      v-if="loading && !info"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="info">
      <UCard>
        <dl class="grid gap-3 text-sm md:grid-cols-2">
          <div>
            <dt class="text-muted">
              {{ t('gates.ci.projectId') }}
            </dt>
            <dd class="flex items-center gap-2">
              <code data-testid="project-id">{{ info.project.id }}</code>
              <UButton
                size="xs"
                variant="ghost"
                icon="i-lucide-copy"
                :aria-label="t('gates.ci.copy')"
                @click="copy(info.project.id)"
              />
            </dd>
          </div>
          <div>
            <dt class="text-muted">
              {{ t('gates.ci.gate') }}
            </dt>
            <dd>
              <ULink
                v-if="info.gate"
                :to="`/gates/${info.gate.id}`"
              >
                {{ info.gate.slug }}
              </ULink>
            </dd>
          </div>
        </dl>
      </UCard>

      <UCard v-if="isOperator">
        <template #header>
          <div class="flex items-center justify-between">
            <div>
              <h2 class="font-semibold">
                {{ t('gates.ci.tokens') }}
              </h2>
              <p class="text-xs text-muted">
                {{ t('gates.ci.tokensHelp') }}
              </p>
            </div>
            <UButton
              icon="i-lucide-key-round"
              :label="t('gates.ci.newToken')"
              :disabled="info.project.archived"
              data-testid="token-create"
              @click="openCreate"
            />
          </div>
        </template>
        <UTable
          :data="tokens"
          :columns="columns"
          :loading="loading"
          :empty="t('gates.ci.noTokens')"
        />
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('gates.ci.badge') }}
          </h2>
        </template>
        <div class="space-y-3 text-sm">
          <p class="text-muted">
            {{ t('gates.ci.badgeHelp') }}
          </p>
          <USwitch
            :model-value="info.badge.enabled"
            :disabled="!isOperator || badgeSaving"
            :loading="badgeSaving"
            :label="t('gates.ci.badge')"
            data-testid="badge-switch"
            @update:model-value="(v: boolean) => setBadge(v)"
          />
          <div
            v-if="info.badge.enabled"
            class="flex items-center gap-3"
          >
            <img
              :src="info.badge.path"
              alt="scanoria"
            >
            <code class="text-xs">{{ origin }}{{ info.badge.path }}</code>
          </div>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('gates.ci.client') }}
          </h2>
        </template>
        <div class="space-y-3 text-sm">
          <p class="text-muted">
            {{ t('gates.ci.clientHelp') }}
          </p>
          <UButton
            icon="i-lucide-download"
            variant="soft"
            to="/api/gates/client"
            external
            download
            :label="t('gates.ci.download')"
          />
          <p class="font-medium">
            {{ t('gates.ci.example') }}
          </p>
          <pre class="overflow-x-auto rounded-md bg-elevated p-3 text-xs"><code data-testid="ci-example">{{ example }}</code></pre>
        </div>
      </UCard>
    </template>

    <UModal
      v-model:open="createOpen"
      :title="t('gates.ci.createTitle')"
      :dismissible="!creating && !created"
    >
      <template #body>
        <div
          v-if="created"
          class="space-y-3"
        >
          <UAlert
            color="warning"
            icon="i-lucide-key-round"
            :title="t('gates.ci.tokenShown')"
            :description="t('gates.ci.tokenStore')"
          />
          <div class="flex items-center gap-2">
            <code
              class="break-all rounded bg-elevated p-2 text-xs select-all"
              data-testid="token-value"
            >{{ created }}</code>
            <UButton
              size="sm"
              icon="i-lucide-copy"
              :label="t('gates.ci.copy')"
              @click="copy(created)"
            />
          </div>
        </div>
        <div
          v-else
          class="space-y-4"
        >
          <UFormField :label="t('gates.ci.name')">
            <UInput
              v-model="form.name"
              data-testid="token-name"
            />
          </UFormField>
          <UFormField
            :label="t('gates.ci.expiresIn')"
            :help="t('gates.ci.expiresInHelp')"
          >
            <UInputNumber
              v-model="form.expires"
              :min="1"
              :max="3650"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            v-if="created"
            :label="t('common.close')"
            @click="closeCreate"
          />
          <template v-else>
            <UButton
              color="neutral"
              variant="ghost"
              :disabled="creating"
              :label="t('common.cancel')"
              @click="createOpen = false"
            />
            <UButton
              :loading="creating"
              :disabled="!form.name.trim()"
              :label="t('common.create')"
              data-testid="token-create-confirm"
              @click="createToken"
            />
          </template>
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="revokeOpen"
      :title="t('gates.ci.revokeTitle')"
      :body="t('gates.ci.revokeBody', { name: target?.name ?? '', prefix: target?.prefix ?? '' })"
      color="error"
      :loading="revoking"
      :confirm-label="t('gates.ci.revoke')"
      @confirm="revoke"
    />
  </PageShell>
</template>
