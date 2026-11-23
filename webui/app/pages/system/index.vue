<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Système : nom de l'appliance et réseaux d'administration (demandes au service root).
-->

<script setup lang="ts">
import { CIDR_RE, fqdnSchema } from '#shared/schemas'

const { t } = useI18n()
useHead({ title: computed(() => t('system.title')) })

const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const { data, state, refresh } = useApplianceState()

// --- Nom ---
const fqdn = ref('')
const fqdnTouched = ref(false)
watch(state, (s) => {
  if (s && !fqdnTouched.value) fqdn.value = s.appliance.fqdn ?? ''
}, { immediate: true })
const fqdnValid = computed(() => fqdnSchema.safeParse(fqdn.value.trim().toLowerCase()).success)
const hostnameModal = ref(false)
const hostnameReq = useHelperRequest()

async function applyHostname() {
  const value = fqdn.value.trim().toLowerCase()
  const r = await hostnameReq.run('/api/system/hostname', { fqdn: value })
  hostnameModal.value = false
  fqdnTouched.value = false
  if (r) await refresh()
}

// --- Réseaux ---
const networksText = ref('')
const networksTouched = ref(false)
const allowLockout = ref(false)
watch(state, (s) => {
  if (s && !networksTouched.value) networksText.value = s.firewall.admin_networks.join('\n')
}, { immediate: true })
const networks = computed(() => networksText.value.split(/[\s,]+/).map(n => n.trim().toLowerCase()).filter(Boolean))
const invalidNetworks = computed(() => networks.value.filter(n => !CIDR_RE.test(n)))
const networksValid = computed(() =>
  networks.value.length >= 1 && networks.value.length <= 64 && invalidNetworks.value.length === 0
  && new Set(networks.value).size === networks.value.length,
)
const networksModal = ref(false)
const networksReq = useHelperRequest()

async function applyNetworks() {
  const r = await networksReq.run('/api/system/admin-networks', {
    networks: networks.value,
    ...(allowLockout.value ? { allow_self_lockout: true } : {}),
  })
  networksModal.value = false
  networksTouched.value = false
  if (r) await refresh()
}
</script>

<template>
  <PageShell :title="t('system.title')">
    <StateAlert :data="data" />

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('system.hostname.title') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('system.hostname.help') }}
        </p>
      </template>
      <div class="space-y-3">
        <p
          v-if="state?.appliance.fqdn"
          class="text-sm"
        >
          {{ t('system.hostname.current', { fqdn: state.appliance.fqdn }) }}
        </p>
        <UFormField
          :label="t('system.hostname.label')"
          :error="fqdn && !fqdnValid ? t('errors.E_VALIDATION') : undefined"
        >
          <UInput
            v-model="fqdn"
            placeholder="analyse.exemple.test"
            class="w-full max-w-md font-mono"
            :disabled="!isAdmin || hostnameReq.running.value"
            @update:model-value="fqdnTouched = true"
          />
        </UFormField>
        <p
          v-if="fqdnValid"
          class="text-xs text-muted"
        >
          {{ t('system.hostname.dnsHint', { fqdn: fqdn.trim().toLowerCase() }) }}
        </p>
        <div class="flex items-center gap-4">
          <UButton
            v-if="isAdmin"
            :disabled="!fqdnValid || fqdn.trim().toLowerCase() === state?.appliance.fqdn"
            :loading="hostnameReq.running.value"
            :label="t('system.hostname.submit')"
            @click="hostnameModal = true"
          />
          <RequestProgress
            :active="hostnameReq.running.value"
            :label="hostnameReq.label.value"
          />
        </div>
      </div>
    </UCard>

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('system.networks.title') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('system.networks.help') }}
        </p>
      </template>
      <div class="space-y-3">
        <p
          v-if="session.state.value.address"
          class="text-sm"
        >
          {{ t('system.networks.yourAddress', { address: session.state.value.address }) }}
        </p>
        <UFormField
          :label="t('system.networks.label')"
          :error="invalidNetworks.length ? t('system.networks.invalid', { value: invalidNetworks[0] }) : undefined"
        >
          <UTextarea
            v-model="networksText"
            :rows="5"
            placeholder="192.0.2.0/24&#10;2001:db8::/32"
            class="w-full max-w-md font-mono"
            :disabled="!isAdmin || networksReq.running.value"
            @update:model-value="networksTouched = true"
          />
        </UFormField>
        <UCheckbox
          v-if="isAdmin"
          v-model="allowLockout"
          :label="t('system.networks.allowLockout')"
          :disabled="networksReq.running.value"
        />
        <div class="flex items-center gap-4">
          <UButton
            v-if="isAdmin"
            :disabled="!networksValid"
            :loading="networksReq.running.value"
            :label="t('system.networks.submit')"
            @click="networksModal = true"
          />
          <RequestProgress
            :active="networksReq.running.value"
            :label="networksReq.label.value"
          />
        </div>
        <p
          v-if="!isAdmin"
          class="text-sm text-muted"
        >
          {{ t('common.adminOnly') }}
        </p>
      </div>
    </UCard>

    <ConfirmModal
      v-model:open="hostnameModal"
      :title="t('system.hostname.confirmTitle')"
      :body="t('system.hostname.confirmBody')"
      color="warning"
      :loading="hostnameReq.running.value"
      :ack="t('common.understood')"
      @confirm="applyHostname"
    >
      <RequestProgress
        :active="hostnameReq.running.value"
        :label="hostnameReq.label.value"
      />
    </ConfirmModal>

    <ConfirmModal
      v-model:open="networksModal"
      :title="t('system.networks.confirmTitle')"
      :body="t('system.networks.confirmBody')"
      :color="allowLockout ? 'error' : 'warning'"
      :loading="networksReq.running.value"
      @confirm="applyNetworks"
    >
      <ul class="font-mono text-sm">
        <li
          v-for="n in networks"
          :key="n"
        >
          {{ n }}
        </li>
      </ul>
      <UAlert
        v-if="allowLockout"
        color="error"
        variant="subtle"
        :title="t('system.networks.lockoutWarning')"
      />
      <RequestProgress
        :active="networksReq.running.value"
        :label="networksReq.label.value"
      />
    </ConfirmModal>
  </PageShell>
</template>
