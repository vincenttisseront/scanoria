<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Accès administrateur d'un module « service » mis en service par l'appliance
(SonarQube) : lien vers l'application, ce qui a été décidé automatiquement, et
réinitialisation du mot de passe admin, affiché une seule fois dans une modale.
-->

<script setup lang="ts">
const props = defineProps<{ moduleId: string, name: string, appUrl: string | null, isAdmin: boolean }>()

const { t } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const req = useHelperRequest()

const confirmOpen = ref(false)
const shownOpen = ref(false)
const password = ref('')
const copied = ref(false)

async function reset() {
  await req.run(`/api/catalog/modules/${encodeURIComponent(props.moduleId)}/admin-password`, {}, { timeoutMs: 10 * 60_000 })
  confirmOpen.value = false
  const r = req.result.value
  if (r?.status !== 'ok') return
  try {
    const out = await api<{ login: string, password: string }>(
      `/api/catalog/modules/${encodeURIComponent(props.moduleId)}/admin-password/reveal`,
      { method: 'POST', body: { request_id: r.id } },
    )
    password.value = out.password
    copied.value = false
    shownOpen.value = true
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error', icon: 'i-lucide-circle-x' })
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(password.value)
    copied.value = true
  }
  catch {
    copied.value = false
  }
}

// Le mot de passe ne reste pas en mémoire de la page après fermeture.
watch(shownOpen, (open) => {
  if (!open) password.value = ''
})
</script>

<template>
  <UCard data-testid="service-admin">
    <template #header>
      <h2 class="font-semibold">
        {{ t('serviceAdmin.title') }}
      </h2>
    </template>
    <div class="space-y-3 text-sm">
      <p class="text-muted">
        {{ t('serviceAdmin.auto') }}
      </p>
      <div class="flex flex-wrap items-center gap-3">
        <UButton
          v-if="appUrl"
          :to="appUrl"
          target="_blank"
          rel="noopener noreferrer"
          icon="i-lucide-external-link"
          variant="soft"
          :label="t('serviceAdmin.open', { name })"
        />
        <span class="text-muted">{{ t('serviceAdmin.login') }}</span>
        <UButton
          v-if="isAdmin"
          data-testid="service-admin-reset"
          icon="i-lucide-key-round"
          color="warning"
          variant="outline"
          :loading="req.running.value"
          :disabled="req.running.value"
          :label="t('serviceAdmin.reset')"
          @click="confirmOpen = true"
        />
      </div>
      <RequestProgress
        :active="req.running.value"
        :label="req.label.value || t('serviceAdmin.resetting')"
      />
    </div>

    <ConfirmModal
      v-model:open="confirmOpen"
      :title="t('serviceAdmin.confirmTitle')"
      :body="t('serviceAdmin.confirmBody')"
      :confirm-label="t('serviceAdmin.confirm')"
      color="warning"
      :loading="req.running.value"
      @confirm="reset"
    />

    <UModal
      v-model:open="shownOpen"
      :title="t('serviceAdmin.shownTitle')"
      :dismissible="false"
    >
      <template #body>
        <div class="space-y-3 text-sm">
          <p>{{ t('serviceAdmin.shownBody') }}</p>
          <div class="flex items-center gap-2">
            <code
              data-testid="service-admin-password"
              class="flex-1 break-all rounded bg-elevated px-2 py-1 font-mono"
            >{{ password }}</code>
            <UButton
              size="sm"
              variant="soft"
              :icon="copied ? 'i-lucide-check' : 'i-lucide-copy'"
              :label="copied ? t('serviceAdmin.copied') : t('serviceAdmin.copy')"
              @click="copy"
            />
          </div>
        </div>
      </template>
      <template #footer>
        <UButton
          :label="t('serviceAdmin.close')"
          @click="shownOpen = false"
        />
      </template>
    </UModal>
  </UCard>
</template>
