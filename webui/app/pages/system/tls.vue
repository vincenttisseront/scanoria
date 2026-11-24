<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

TLS : certificat actif, AC interne (téléchargement), renouvellement, import.
-->

<script setup lang="ts">
import { requestParamSchemas } from '#shared/schemas'

const { t } = useI18n()
useHead({ title: computed(() => t('tls.title')) })

const session = useSession()
const isAdmin = computed(() => session.can('admin'))
const fmt = useFormat()
const { data, state, failed, refresh } = useApplianceState()

// --- Renouvellement ---
const renewModal = ref(false)
const renewReq = useHelperRequest()
async function renew() {
  const r = await renewReq.run('/api/system/tls/issue', { force: true })
  renewModal.value = false
  if (r) await refresh()
}

// --- Import ---
const pem = reactive({ cert: '', key: '', chain: '' })
const importModal = ref(false)
const importReq = useHelperRequest()
const importParams = computed(() => ({
  cert_pem: pem.cert.trim() ? `${pem.cert.trim()}\n` : '',
  key_pem: pem.key.trim() ? `${pem.key.trim()}\n` : '',
  ...(pem.chain.trim() ? { chain_pem: `${pem.chain.trim()}\n` } : {}),
}))
const importValid = computed(() => requestParamSchemas['import-certificate'].safeParse(importParams.value).success)

async function loadFile(field: 'cert' | 'key' | 'chain', event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file && file.size <= 65536) pem[field] = await file.text()
  input.value = ''
}

async function doImport() {
  const r = await importReq.run('/api/system/tls/import', importParams.value)
  importModal.value = false
  pem.key = ''
  if (r?.status === 'ok') {
    pem.cert = ''
    pem.chain = ''
  }
  if (r) await refresh()
}
</script>

<template>
  <PageShell :title="t('tls.title')">
    <StateAlert
      :data="data"
      :failed="failed"
    />

    <UCard v-if="state">
      <template #header>
        <h2 class="font-semibold">
          {{ t('dashboard.tls') }}
        </h2>
      </template>
      <dl class="grid gap-2 text-sm md:grid-cols-[max-content_1fr] md:gap-x-6">
        <dt class="text-muted">
          {{ t('tls.mode') }}
        </dt>
        <dd>{{ t(`tls.modes.${state.tls.mode}`) }}</dd>
        <dt class="text-muted">
          {{ t('tls.names') }}
        </dt>
        <dd class="font-mono">
          {{ state.tls.subject_alt_names.join(', ') || '—' }}
        </dd>
        <dt class="text-muted">
          {{ t('tls.validity') }}
        </dt>
        <dd>{{ fmt.date(state.tls.not_before) }} → {{ fmt.date(state.tls.not_after) }}</dd>
        <dt class="text-muted">
          {{ t('tls.fingerprint') }}
        </dt>
        <dd class="font-mono text-xs break-all">
          {{ fmt.fingerprint(state.tls.fingerprint_sha256) }}
        </dd>
      </dl>
      <div
        v-if="isAdmin"
        class="mt-4 flex items-center gap-4"
      >
        <UButton
          icon="i-lucide-rotate-cw"
          color="neutral"
          variant="outline"
          :loading="renewReq.running.value"
          :label="t('tls.renew')"
          @click="renewModal = true"
        />
        <RequestProgress
          :active="renewReq.running.value"
          :label="renewReq.label.value"
        />
      </div>
    </UCard>

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('tls.caTitle') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('tls.caHelp') }}
        </p>
      </template>
      <div class="space-y-3 text-sm">
        <p v-if="state?.tls.ca_fingerprint_sha256">
          <span class="text-muted">{{ t('tls.caFingerprint') }}</span><br>
          <span class="font-mono text-xs break-all">{{ fmt.fingerprint(state.tls.ca_fingerprint_sha256) }}</span>
        </p>
        <UButton
          icon="i-lucide-download"
          href="/api/system/tls/ca"
          external
          download="scanoria-ca.crt"
          :label="t('tls.downloadCa')"
        />
      </div>
    </UCard>

    <UCard v-if="isAdmin">
      <template #header>
        <h2 class="font-semibold">
          {{ t('tls.importTitle') }}
        </h2>
        <p class="text-sm text-muted">
          {{ t('tls.importHelp') }}
        </p>
      </template>
      <div class="space-y-4">
        <UFormField
          v-for="field in (['cert', 'key', 'chain'] as const)"
          :key="field"
          :label="t(field === 'cert' ? 'tls.certPem' : field === 'key' ? 'tls.keyPem' : 'tls.chainPem')"
        >
          <UTextarea
            v-model="pem[field]"
            :rows="5"
            class="w-full font-mono text-xs"
            autocomplete="off"
            spellcheck="false"
            :disabled="importReq.running.value"
            :placeholder="field === 'key' ? '-----BEGIN PRIVATE KEY-----' : '-----BEGIN CERTIFICATE-----'"
          />
          <template #hint>
            <label class="cursor-pointer text-primary">
              {{ t('tls.loadFile') }}
              <input
                type="file"
                class="sr-only"
                accept=".pem,.crt,.cer,.key,text/plain"
                @change="loadFile(field, $event)"
              >
            </label>
          </template>
        </UFormField>
        <div class="flex items-center gap-4">
          <UButton
            icon="i-lucide-upload"
            :disabled="!importValid"
            :loading="importReq.running.value"
            :label="t('tls.importSubmit')"
            @click="importModal = true"
          />
          <RequestProgress
            :active="importReq.running.value"
            :label="importReq.label.value"
          />
        </div>
      </div>
    </UCard>

    <ConfirmModal
      v-model:open="renewModal"
      :title="t('tls.renewConfirmTitle')"
      :body="t('tls.renewConfirmBody')"
      :loading="renewReq.running.value"
      @confirm="renew"
    >
      <RequestProgress
        :active="renewReq.running.value"
        :label="renewReq.label.value"
      />
    </ConfirmModal>

    <ConfirmModal
      v-model:open="importModal"
      :title="t('tls.importConfirmTitle')"
      :body="t('tls.importConfirmBody')"
      :loading="importReq.running.value"
      @confirm="doImport"
    >
      <RequestProgress
        :active="importReq.running.value"
        :label="importReq.label.value"
      />
    </ConfirmModal>
  </PageShell>
</template>
