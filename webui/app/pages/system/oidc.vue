<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Émetteurs OIDC de confiance pour la CI sans secret (J4, 0.8 chantier C) :
déclarés automatiquement par forge, ajout manuel, activation et
désactivation (jamais de suppression), refus comptés depuis le démarrage.
Administrateur.
-->

<script setup lang="ts">
const { t, te } = useI18n()
useHead({ title: computed(() => t('oidcIssuers.title')) })
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface Issuer { id: string, kind: string, issuer: string, audience: string, enabled: boolean, bindings: number, jwks_fetched_at: string | null }
const issuers = ref<Issuer[]>([])
const refusals = ref<Record<string, number>>({})
const loading = ref(false)

function message(err: unknown): string {
  const code = gateErrorCode(err)
  return code && te(`errors.${code}`) ? t(`errors.${code}`) : errorMessage(err)
}

async function load() {
  loading.value = true
  try {
    const res = await api<{ issuers: Issuer[], refusals: Record<string, number> }>('/api/ci/issuers')
    issuers.value = res.issuers
    refusals.value = res.refusals
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(() => {
  if (session.can('admin')) void load()
})

const kinds = [{ label: 'Forgejo', value: 'forgejo' }, { label: 'GitHub', value: 'github' }, { label: 'GitLab', value: 'gitlab' }]
const issuerForm = reactive({ kind: 'forgejo', issuer: '', audience: 'scanoria' })
const canAdd = computed(() => issuerForm.issuer.trim().startsWith('https://'))
const addOpen = ref(false)
const saving = ref(false)
async function add() {
  saving.value = true
  try {
    await api('/api/ci/issuers', { method: 'POST', body: { kind: issuerForm.kind, issuer: issuerForm.issuer.trim(), audience: issuerForm.audience.trim() || undefined } })
    addOpen.value = false
    issuerForm.issuer = ''
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

const toggleOpen = ref(false)
const toggling = ref(false)
const target = ref<Issuer | null>(null)
function askToggle(i: Issuer) {
  target.value = i
  toggleOpen.value = true
}
async function toggle() {
  if (!target.value) return
  toggling.value = true
  try {
    await api(`/api/ci/issuers/${target.value.id}`, { method: 'PATCH', body: { enabled: !target.value.enabled } })
    toggleOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    toggling.value = false
  }
}
const refusalList = computed(() => Object.entries(refusals.value).filter(([, n]) => n > 0))
</script>

<template>
  <PageShell :title="t('oidcIssuers.title')">
    <UAlert
      v-if="!session.can('admin')"
      color="neutral"
      variant="subtle"
      :title="t('common.adminOnly')"
    />
    <template v-else>
      <UCard>
        <template #header>
          <div class="flex items-center justify-between">
            <p class="text-sm text-muted">
              {{ t('oidcIssuers.help') }}
            </p>
            <UButton
              icon="i-lucide-plus"
              :label="t('oidcIssuers.add')"
              data-testid="oidc-issuer-add"
              @click="addOpen = true"
            />
          </div>
        </template>
        <div
          v-if="loading && !issuers.length"
          class="flex items-center gap-2 text-sm text-muted"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="animate-spin"
          />
          {{ t('app.loading') }}
        </div>
        <p
          v-else-if="!issuers.length"
          class="text-sm text-muted"
        >
          {{ t('oidcIssuers.none') }}
        </p>
        <ul
          v-else
          class="divide-y divide-default text-sm"
        >
          <li
            v-for="i in issuers"
            :key="i.id"
            class="flex flex-wrap items-center justify-between gap-2 py-2"
            data-testid="oidc-issuer"
          >
            <div>
              <code>{{ i.issuer }}</code>
              <UBadge
                class="ms-2"
                variant="subtle"
                :color="i.enabled ? 'success' : 'neutral'"
                :label="i.enabled ? t('oidcIssuers.enabled') : t('oidcIssuers.disabled')"
              />
              <div class="text-xs text-muted">
                {{ t('oidcIssuers.meta', { kind: i.kind, audience: i.audience, n: i.bindings }) }}
                · {{ i.jwks_fetched_at ? t('oidcIssuers.jwks', { date: fmt.date(i.jwks_fetched_at) }) : t('oidcIssuers.noJwks') }}
              </div>
            </div>
            <UButton
              size="xs"
              variant="soft"
              :color="i.enabled ? 'warning' : 'primary'"
              :label="i.enabled ? t('oidcIssuers.disable') : t('oidcIssuers.enable')"
              @click="askToggle(i)"
            />
          </li>
        </ul>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('oidcIssuers.refusals') }}
          </h2>
        </template>
        <p
          v-if="!refusalList.length"
          class="text-sm text-muted"
        >
          {{ t('oidcIssuers.noRefusals') }}
        </p>
        <ul
          v-else
          class="text-sm"
        >
          <li
            v-for="[reason, n] in refusalList"
            :key="reason"
          >
            <code>{{ reason }}</code> : {{ n }}
          </li>
        </ul>
      </UCard>
    </template>

    <UModal
      v-model:open="addOpen"
      :title="t('oidcIssuers.add')"
      :dismissible="!saving"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField :label="t('oidcIssuers.kind')">
            <USelect
              v-model="issuerForm.kind"
              :items="kinds"
              class="w-full"
            />
          </UFormField>
          <UFormField
            :label="t('oidcIssuers.issuer')"
            :help="t('oidcIssuers.issuerHelp')"
          >
            <UInput
              v-model="issuerForm.issuer"
              placeholder="https://forge.exemple.test/api/actions"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('oidcIssuers.audience')">
            <UInput
              v-model="issuerForm.audience"
              class="w-full"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            variant="ghost"
            color="neutral"
            :label="t('common.cancel')"
            :disabled="saving"
            @click="addOpen = false"
          />
          <UButton
            :loading="saving"
            :disabled="!canAdd"
            :label="t('common.save')"
            @click="add"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="toggleOpen"
      :title="target?.enabled ? t('oidcIssuers.disableTitle') : t('oidcIssuers.enableTitle')"
      :body="t(target?.enabled ? 'oidcIssuers.disableBody' : 'oidcIssuers.enableBody', { issuer: target?.issuer ?? '' })"
      :color="target?.enabled ? 'warning' : 'primary'"
      :loading="toggling"
      :confirm-label="target?.enabled ? t('oidcIssuers.disable') : t('oidcIssuers.enable')"
      @confirm="toggle"
    />
  </PageShell>
</template>
