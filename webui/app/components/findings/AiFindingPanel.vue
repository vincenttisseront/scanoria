<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

0.7 (contrat 32) : résultat d'un module d'analyse par IA, dans le panneau de
détail. Informatif et hors verdict tant qu'il n'est pas confirmé ; modèle et
début de son empreinte, mention « proposé par IA ». Une personne de rôle
operator ou plus le confirme dans une modale de la console : il devient un
résultat normal et compte dans le verdict des analyses évaluées ensuite. Le
rejeter, c'est le classer « faux positif » avec le statut habituel (ces deux
gestes mesurent l'accord IA/humain, I24).
-->

<script setup lang="ts">
const props = defineProps<{ findingId: string, origin: string | null | undefined }>()
const emit = defineEmits<{ confirmed: [] }>()
const { t } = useI18n()
const { api, errorMessage } = useApi()
const session = useSession()
const fmt = useFormat()
const toast = useToast()

interface AiInfo {
  confirmed: boolean
  confirmed_at: string | null
  confirmed_by: string | null
  model: string | null
  digest: string | null
}
const info = ref<AiInfo | null>(null)
const loading = ref(false)
const open = ref(false)
const busy = ref(false)

async function load() {
  info.value = null
  if (props.origin !== 'ai') return
  loading.value = true
  try {
    info.value = await api<AiInfo>(`/api/findings/${props.findingId}/ai`)
  }
  catch {
    info.value = null
  }
  finally {
    loading.value = false
  }
}
watch(() => [props.findingId, props.origin], load, { immediate: true })

async function confirmFinding() {
  busy.value = true
  try {
    info.value = await api<AiInfo>(`/api/findings/${props.findingId}/ai-confirm`, { method: 'POST' })
    open.value = false
    toast.add({ title: t('aiFindings.confirmed'), color: 'success' })
    emit('confirmed')
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    busy.value = false
  }
}
</script>

<template>
  <UCard
    v-if="origin === 'ai'"
    data-testid="ai-finding-panel"
  >
    <template #header>
      <div class="flex flex-wrap items-center gap-2">
        <FindingsAiOriginBadge
          :origin="origin"
          :confirmed="info?.confirmed ?? null"
        />
        <h4 class="font-semibold">
          {{ t('aiFindings.title') }}
        </h4>
      </div>
    </template>
    <div
      v-if="loading"
      class="flex items-center gap-2 text-sm text-muted"
      data-testid="ai-finding-loading"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <div
      v-else
      class="space-y-2 text-sm"
    >
      <p v-if="info?.confirmed">
        {{ t('aiFindings.confirmedBy', { user: info.confirmed_by ?? '—', date: info.confirmed_at ? fmt.date(info.confirmed_at) : '—' }) }}
      </p>
      <p
        v-else
        data-testid="ai-finding-pending"
      >
        {{ t('aiFindings.pending') }}
      </p>
      <p class="text-xs text-muted">
        {{ t('aiFindings.proposedBy') }}
        <span
          v-if="info?.model"
          class="font-mono"
          data-testid="ai-finding-model"
        >· {{ info.model }}<template v-if="info.digest"> ({{ info.digest }})</template></span>
      </p>
      <div
        v-if="info && !info.confirmed"
        class="flex flex-wrap items-center gap-2"
      >
        <UButton
          v-if="session.can('operator')"
          size="sm"
          icon="i-lucide-check"
          :label="t('aiFindings.confirm')"
          data-testid="ai-finding-confirm"
          @click="open = true"
        />
        <span class="text-xs text-muted">{{ t('aiFindings.rejectHelp') }}</span>
      </div>
    </div>
    <UModal
      v-model:open="open"
      :title="t('aiFindings.confirmTitle')"
      :dismissible="!busy"
    >
      <template #body>
        <p class="text-sm">
          {{ t('aiFindings.confirmBody') }}
        </p>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :label="t('common.cancel')"
            :disabled="busy"
            @click="open = false"
          />
          <UButton
            :label="t('aiFindings.confirm')"
            :loading="busy"
            data-testid="ai-finding-confirm-send"
            @click="confirmFinding"
          />
        </div>
      </template>
    </UModal>
  </UCard>
</template>
