<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Diagnostic d'une analyse en échec (I15) : cause probable, correction et
étapes. Quand un réglage sûr existe (délai d'un module), il est recalculé
par le serveur à partir des faits, jamais repris du modèle, et appliqué par
un opérateur dans une modale de la console ; l'application est auditée.
-->

<script setup lang="ts">
const props = defineProps<{ scanId: string }>()
const { t } = useI18n()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()

interface Proposal { kind: 'timeout', module: string, current_s: number, proposed_s: number }
const proposal = ref<Proposal | null>(null)
const open = ref(false)
const busy = ref(false)
const canApply = computed(() => session.can('operator'))

const minutes = (s: number) => (s % 60 === 0 ? `${s / 60} min` : `${s} s`)
const list = (v: unknown) => (Array.isArray(v) ? v as string[] : [])
const vars = computed(() => (proposal.value
  ? { module: proposal.value.module, from: minutes(proposal.value.current_s), to: minutes(proposal.value.proposed_s) }
  : { module: '', from: '', to: '' }))

async function loadProposal(task: { status: string } | null) {
  proposal.value = null
  if (!canApply.value || task?.status !== 'done') return
  try {
    proposal.value = (await api<{ proposal: Proposal | null }>('/api/ai/diagnosis/proposal', { query: { scan_id: props.scanId } })).proposal
  }
  catch {
    proposal.value = null
  }
}

async function apply() {
  if (!proposal.value) return
  busy.value = true
  try {
    await api('/api/ai/diagnosis/apply', { method: 'POST', body: { scan_id: props.scanId, module: proposal.value.module, proposed_s: proposal.value.proposed_s } })
    toast.add({ title: t('ai.diagnosis.applied', vars.value), color: 'success' })
    open.value = false
    proposal.value = null
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
  <AiTaskPanel
    kind="diagnose-scan"
    :subject-id="scanId"
    :title="t('ai.diagnosis.title')"
    icon="i-lucide-stethoscope"
    @loaded="loadProposal"
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-diagnosis"
      >
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-muted">{{ t('ai.diagnosis.cause') }}</span>
          <UBadge
            color="warning"
            variant="subtle"
            :label="t(`ai.diagnosis.causes.${String(output.cause)}`)"
          />
          <span
            v-if="output.module"
            class="font-mono text-xs"
          >{{ output.module }}</span>
        </div>
        <p>{{ output.summary }}</p>
        <div>
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.diagnosis.fix') }}
          </h4>
          <p>{{ output.fix }}</p>
        </div>
        <div v-if="list(output.steps).length">
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.diagnosis.steps') }}
          </h4>
          <ol class="list-decimal ps-5">
            <li
              v-for="(s, i) in list(output.steps)"
              :key="i"
            >
              {{ s }}
            </li>
          </ol>
        </div>
        <div
          v-if="proposal"
          class="flex flex-wrap items-center gap-2 rounded-md bg-elevated p-2"
          data-testid="ai-diagnosis-proposal"
        >
          <span>{{ t('ai.diagnosis.proposal', vars) }}</span>
          <UButton
            size="xs"
            icon="i-lucide-timer"
            :label="t('ai.diagnosis.apply')"
            data-testid="ai-diagnosis-apply"
            @click="open = true"
          />
        </div>
      </div>
    </template>
  </AiTaskPanel>
  <ConfirmModal
    v-model:open="open"
    :title="t('ai.diagnosis.applyTitle', vars)"
    :body="t('ai.diagnosis.applyBody', vars)"
    :confirm-label="t('ai.diagnosis.apply')"
    :loading="busy"
    @confirm="apply"
  />
</template>
