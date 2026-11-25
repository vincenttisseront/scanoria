<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Exceptions à approuver (F5, J15), pour les administrateurs : demandes en
attente, tous projets. Approuver ou refuser passe par une modale avec un motif
de décision. Règles fixes, appliquées par le serveur et rappelées ici : on ne
décide ni sa propre demande, ni une demande sur un commit dont on est
l'auteur ; un compte « agent » ou « bot », un jeton ou l'IA ne décident jamais.
Après une approbation, le verdict des dernières analyses du projet est
recalculé sans réanalyse ; la liste se rafraîchit sans recharger la page.
-->

<script setup lang="ts">
const { t } = useI18n()
useHead({ title: computed(() => t('triage.approvals.title')) })

const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()

interface Pending {
  id: string
  project_id: string
  project_slug: string
  project_name: string
  kind: string
  target: Record<string, string>
  reason: string
  expires_on: string
  requested_via: string
  requester_label: string | null
  requester_is_human: boolean
  commit_authors: string[]
  created_by: string | null
  created_at: string
  expired: boolean
  cannot_decide: string | null
}

const items = ref<Pending[]>([])
const loading = ref(false)
const loadError = ref('')

async function load() {
  loading.value = true
  try {
    items.value = (await api<{ items: Pending[] }>('/api/exceptions/pending')).items
    loadError.value = ''
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

function targetText(e: Pending): string {
  return Object.entries(e.target).map(([k, v]) => `${k}=${v}`).join(' · ')
}
function requester(e: Pending): string {
  const who = e.created_by ?? e.requester_label ?? '—'
  return e.requester_is_human ? who : `${who} (${t('triage.approvals.nonHuman')})`
}

const open = ref(false)
const deciding = ref(false)
const current = ref<Pending | null>(null)
const form = reactive<{ decision: 'approved' | 'refused', reason: string }>({ decision: 'approved', reason: '' })
function ask(e: Pending, decision: 'approved' | 'refused') {
  current.value = e
  Object.assign(form, { decision, reason: '' })
  open.value = true
}
async function decide() {
  if (!current.value) return
  deciding.value = true
  try {
    const r = await api<{ reevaluated: unknown[] }>(`/api/exceptions/${current.value.id}/decision`, { method: 'POST', body: { decision: form.decision, reason: form.reason.trim() } })
    toast.add({
      title: form.decision === 'approved' ? t('triage.approvals.approvedDone', { count: r.reevaluated?.length ?? 0 }) : t('triage.approvals.refusedDone'),
      color: 'success',
    })
    open.value = false
    await load()
    await refreshPendingCount()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    deciding.value = false
  }
}
const { refresh: refreshPendingCount } = usePendingExceptions()
</script>

<template>
  <PageShell :title="t('triage.approvals.title')">
    <template #actions>
      <UButton
        to="/findings/exceptions"
        icon="i-lucide-shield-off"
        color="neutral"
        variant="ghost"
        :label="t('findings.exceptionsLink')"
      />
    </template>
    <UAlert
      v-if="!session.can('admin')"
      color="neutral"
      variant="subtle"
      icon="i-lucide-lock"
      :title="t('triage.approvals.adminOnly')"
    />
    <template v-else>
      <p class="text-sm text-muted">
        {{ t('triage.approvals.rules') }}
      </p>
      <UAlert
        v-if="loadError"
        color="error"
        variant="subtle"
        icon="i-lucide-circle-x"
        :title="loadError"
      />
      <UCard>
        <div
          v-if="loading"
          class="flex justify-center py-6"
          data-testid="approvals-loading"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-6 animate-spin"
          />
        </div>
        <p
          v-else-if="!items.length"
          class="text-sm text-muted"
          data-testid="approvals-empty"
        >
          {{ t('triage.approvals.none') }}
        </p>
        <ul
          v-else
          class="divide-y divide-default text-sm"
        >
          <li
            v-for="e in items"
            :key="e.id"
            class="flex flex-wrap items-start justify-between gap-3 py-3"
            data-testid="pending"
          >
            <div class="min-w-0 space-y-1">
              <div class="flex flex-wrap items-center gap-2">
                <NuxtLink
                  :to="`/findings/exceptions?project_id=${e.project_id}`"
                  class="font-medium underline"
                >
                  {{ e.project_name }}
                </NuxtLink>
                <UBadge
                  variant="subtle"
                  color="neutral"
                  :label="t(`findings.exceptions.kinds.${e.kind}`)"
                />
                <span class="font-mono text-xs break-all">{{ targetText(e) }}</span>
                <UBadge
                  v-if="e.expired"
                  color="warning"
                  variant="subtle"
                  :label="t('findings.exceptions.expired')"
                />
              </div>
              <p class="whitespace-pre-wrap break-words">
                {{ e.reason }}
              </p>
              <p class="text-xs text-muted">
                {{ t('findings.exceptions.expires') }} : {{ e.expires_on }} · {{ t('triage.approvals.requestedBy', { who: requester(e), via: t(`triage.approvals.via.${e.requested_via}`), date: fmt.date(e.created_at) }) }}
              </p>
              <p
                v-if="e.commit_authors.length"
                class="text-xs text-muted"
              >
                {{ t('triage.approvals.authors', { authors: e.commit_authors.join(', ') }) }}
              </p>
              <p
                v-if="e.cannot_decide"
                class="text-xs text-warning"
                data-testid="cannot-decide"
              >
                {{ t(`triage.approvals.cannot.${e.cannot_decide}`) }}
              </p>
            </div>
            <div
              v-if="!e.cannot_decide"
              class="flex gap-2"
            >
              <UButton
                color="success"
                variant="outline"
                icon="i-lucide-check"
                :disabled="e.expired"
                :label="t('triage.approvals.approve')"
                data-testid="approve"
                @click="ask(e, 'approved')"
              />
              <UButton
                color="error"
                variant="ghost"
                icon="i-lucide-x"
                :label="t('triage.approvals.refuse')"
                data-testid="refuse"
                @click="ask(e, 'refused')"
              />
            </div>
          </li>
        </ul>
      </UCard>
    </template>

    <UModal
      v-model:open="open"
      :title="form.decision === 'approved' ? t('triage.approvals.approveTitle') : t('triage.approvals.refuseTitle')"
      :dismissible="!deciding"
    >
      <template #body>
        <div
          v-if="current"
          class="space-y-3 text-sm"
        >
          <p>
            <span class="font-medium">{{ current.project_name }}</span> · <span class="font-mono text-xs">{{ targetText(current) }}</span>
          </p>
          <p class="whitespace-pre-wrap break-words text-muted">
            {{ current.reason }}
          </p>
          <p
            v-if="form.decision === 'approved'"
            class="text-xs"
          >
            {{ t('triage.approvals.approveBody', { date: current.expires_on }) }}
          </p>
          <UFormField :label="t('triage.approvals.decisionReason')">
            <UTextarea
              v-model="form.reason"
              :maxlength="2000"
              class="w-full"
              data-testid="decision-reason"
            />
          </UFormField>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="deciding"
            :label="t('common.cancel')"
            @click="open = false"
          />
          <UButton
            :color="form.decision === 'approved' ? 'success' : 'error'"
            :loading="deciding"
            :disabled="form.reason.trim().length < 3"
            :label="form.decision === 'approved' ? t('triage.approvals.approve') : t('triage.approvals.refuse')"
            data-testid="decision-confirm"
            @click="decide"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
