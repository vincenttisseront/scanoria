<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Intégration CI d'un projet (0.8, chantier C) : PR d'intégration (J2) et son
état, protection de branche proposée puis appliquée après confirmation d'un
administrateur (modale qui montre la règle exacte), case « chaîne autonome »
(J16), liaisons OIDC (J4, CI sans secret) et modèles CI officiels (J3).
-->

<script setup lang="ts">
const props = defineProps<{ projectId: string }>()

interface Binding { id: string, issuer_id: string, issuer: string, kind: string, repository: string, repository_id: string | null, ref_patterns: string[] }
interface IntegrationRequest {
  id: string
  kind: 'ci-pr' | 'branch-protection'
  state: 'proposed' | 'open' | 'merged' | 'closed' | 'applied' | 'declined' | 'error'
  external_id: string | null
  detail: Record<string, unknown>
  decided_by_username: string | null
  updated_at: string
}
interface CiState {
  release_mode: 'pull' | 'push' | 'off'
  autonomous_chain: boolean
  forge: { id: string, kind: string, name: string } | null
  repository: string | null
  default_branch: string | null
  detected_ci: { kind: string, path: string }[] | null
  template: string | null
  contexts: { pr: string, release_gate: string }
  requests: IntegrationRequest[]
  bindings: Binding[]
  issuers: { id: string, kind: string, issuer: string, enabled: boolean }[]
  console_url: string | null
  client_sha256: string | null
}

const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()
const isOperator = computed(() => session.can('operator'))
const isAdmin = computed(() => session.can('admin'))

const state = ref<CiState | null>(null)
const loading = ref(false)
const loadError = ref('')

function message(err: unknown): string {
  const code = gateErrorCode(err)
  return code && te(`errors.${code}`) ? t(`errors.${code}`) : errorMessage(err)
}

async function load() {
  loading.value = true
  try {
    state.value = await api<CiState>(`/api/projects/${props.projectId}/ci`)
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

const prRequest = computed(() => state.value?.requests.find(r => r.kind === 'ci-pr') ?? null)
const protection = computed(() => state.value?.requests.find(r => r.kind === 'branch-protection') ?? null)
const stateColor = (s: IntegrationRequest['state']) => (s === 'merged' || s === 'applied' ? 'success' : s === 'error' ? 'error' : s === 'open' || s === 'proposed' ? 'info' : 'neutral')
const detailText = (r: IntegrationRequest | null, key: string) => (r && typeof r.detail[key] === 'string' ? r.detail[key] as string : '')

// --- PR d'intégration (J2) ---
const opening = ref(false)
async function openPr() {
  opening.value = true
  try {
    const res = await api<{ outcome: string, code?: string }>(`/api/projects/${props.projectId}/ci/pr`, { method: 'POST' })
    toast.add({ title: t(`ciIntegration.pr.outcome.${res.outcome}`), color: res.outcome === 'error' ? 'error' : 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    opening.value = false
  }
}

// --- Protection de branche : règle exacte montrée, puis décision d'un administrateur ---
const protectOpen = ref(false)
const protectAction = ref<'apply' | 'decline'>('apply')
const includeReleaseGate = ref(false)
const deciding = ref(false)
const ruleContexts = computed(() => state.value ? [state.value.contexts.pr, ...(includeReleaseGate.value ? [state.value.contexts.release_gate] : [])] : [])
function askProtection(action: 'apply' | 'decline') {
  protectAction.value = action
  includeReleaseGate.value = false
  protectOpen.value = true
}
async function decide() {
  if (!protection.value) return
  deciding.value = true
  try {
    const res = await api<IntegrationRequest>(`/api/projects/${props.projectId}/ci/protection`, {
      method: 'POST',
      body: { request_id: protection.value.id, action: protectAction.value, include_release_gate: includeReleaseGate.value, confirm: true },
    })
    if (res.state === 'proposed' && res.detail.error) toast.add({ title: t('ciIntegration.protection.failed'), color: 'error' })
    else toast.add({ title: t(`ciIntegration.protection.done.${res.state}`), color: 'success' })
    protectOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    deciding.value = false
  }
}
const proposing = ref(false)
async function proposeAgain() {
  proposing.value = true
  try {
    await api(`/api/projects/${props.projectId}/ci/protection-request`, { method: 'POST' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    proposing.value = false
  }
}

// --- J16 : chaîne autonome ---
const chainSaving = ref(false)
async function setChain(enabled: boolean) {
  chainSaving.value = true
  try {
    await api(`/api/projects/${props.projectId}/ci/settings`, { method: 'PATCH', body: { autonomous_chain: enabled } })
    toast.add({ title: t(enabled ? 'ciIntegration.chain.on' : 'ciIntegration.chain.off'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    chainSaving.value = false
  }
}

// --- Liaisons OIDC (J4) ---
const bindingForm = reactive({ issuer_id: '', repository: '', refs: 'refs/heads/main, refs/tags/*' })
const bindingOpen = ref(false)
const bindingSaving = ref(false)
const issuerItems = computed(() => (state.value?.issuers ?? []).map(i => ({ label: `${i.issuer} (${i.kind})`, value: i.id })))
function openBinding() {
  bindingForm.issuer_id = state.value?.issuers[0]?.id ?? ''
  bindingForm.repository = state.value?.repository ?? ''
  bindingForm.refs = 'refs/heads/main, refs/tags/*'
  bindingOpen.value = true
}
async function addBinding() {
  bindingSaving.value = true
  try {
    await api(`/api/projects/${props.projectId}/ci/bindings`, {
      method: 'POST',
      body: { issuer_id: bindingForm.issuer_id, repository: bindingForm.repository.trim(), ref_patterns: bindingForm.refs.split(/[\s,]+/).filter(Boolean) },
    })
    bindingOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    bindingSaving.value = false
  }
}
const removeOpen = ref(false)
const removing = ref(false)
const removeTarget = ref<Binding | null>(null)
function askRemove(b: Binding) {
  removeTarget.value = b
  removeOpen.value = true
}
const resetOpen = ref(false)
const resetting = ref(false)
function askReset(b: Binding) {
  removeTarget.value = b
  resetOpen.value = true
}
async function resetPin() {
  if (!removeTarget.value) return
  resetting.value = true
  try {
    await api(`/api/projects/${props.projectId}/ci/bindings/${removeTarget.value.id}`, { method: 'PATCH', body: { reset_repository_id: true } })
    resetOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    resetting.value = false
  }
}
async function removeBinding() {
  if (!removeTarget.value) return
  removing.value = true
  try {
    await api(`/api/projects/${props.projectId}/ci/bindings/${removeTarget.value.id}`, { method: 'DELETE' })
    removeOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    removing.value = false
  }
}

const templates = [
  { file: 'github/scanoria.yml', label: 'GitHub Actions', render: true },
  { file: 'forgejo/scanoria.yml', label: 'Forgejo Actions', render: true },
  { file: 'gitlab/scanoria.yml', label: 'GitLab CI', render: false },
  { file: 'jenkins/vars/scanoria.groovy', label: 'Jenkins', render: false },
  { file: 'tekton/scanoria-task.yaml', label: 'Tekton', render: false },
  { file: 'scanoria-ci.sh', label: 'scanoria-ci.sh', render: false },
]
const templateUrl = (tpl: { file: string, render: boolean }) =>
  `/api/ci/templates?file=${encodeURIComponent(tpl.file)}${tpl.render ? `&project=${props.projectId}` : ''}`
</script>

<template>
  <div class="space-y-4">
    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-x"
      :title="loadError"
    />
    <div
      v-if="loading && !state"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="state">
      <UCard data-testid="ci-integration">
        <template #header>
          <h2 class="font-semibold">
            {{ t('ciIntegration.pr.title') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('ciIntegration.pr.help') }}
          </p>
        </template>
        <div class="space-y-3 text-sm">
          <p v-if="!state.forge">
            {{ t('ciIntegration.pr.noForge') }}
          </p>
          <template v-else>
            <p class="text-muted">
              {{ t('ciIntegration.pr.decided', { ci: state.template ?? '—', mode: t(`ciIntegration.mode.${state.release_mode}`) }) }}
            </p>
            <div
              v-if="prRequest"
              class="flex flex-wrap items-center gap-2"
            >
              <UBadge
                :color="stateColor(prRequest.state)"
                variant="subtle"
                :label="t(`ciIntegration.state.${prRequest.state}`)"
              />
              <ULink
                v-if="detailText(prRequest, 'url')"
                :to="detailText(prRequest, 'url')"
                target="_blank"
                external
              >
                {{ t('ciIntegration.pr.link', { n: prRequest.external_id }) }}
              </ULink>
              <span class="text-xs text-muted">{{ fmt.date(prRequest.updated_at) }}</span>
            </div>
            <UAlert
              v-if="prRequest?.state === 'error'"
              color="error"
              variant="subtle"
              :title="t('ciIntegration.pr.error', { code: detailText(prRequest, 'error') })"
              :description="detailText(prRequest, 'missing_permission') ? t('ciIntegration.missing', { permission: detailText(prRequest, 'missing_permission') }) : undefined"
            />
            <pre
              v-if="detailText(prRequest, 'manual')"
              class="overflow-x-auto rounded-md bg-elevated p-3 text-xs"
            ><code>{{ detailText(prRequest, 'manual') }}</code></pre>
            <UButton
              v-if="isOperator && (!prRequest || prRequest.state === 'closed' || prRequest.state === 'error')"
              icon="i-lucide-git-pull-request-arrow"
              :loading="opening"
              :label="prRequest ? t('ciIntegration.pr.reopen') : t('ciIntegration.pr.open')"
              data-testid="ci-pr-open"
              @click="openPr"
            />
          </template>
        </div>
      </UCard>

      <UCard v-if="state.forge">
        <template #header>
          <h2 class="font-semibold">
            {{ t('ciIntegration.protection.title') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('ciIntegration.protection.help') }}
          </p>
        </template>
        <div class="space-y-3 text-sm">
          <div
            v-if="protection"
            class="flex flex-wrap items-center gap-2"
          >
            <UBadge
              :color="stateColor(protection.state)"
              variant="subtle"
              :label="t(`ciIntegration.state.${protection.state}`)"
            />
            <code class="text-xs">{{ (protection.detail.contexts as string[] | undefined)?.join(', ') }}</code>
            <span
              v-if="protection.decided_by_username"
              class="text-xs text-muted"
            >{{ t('ciIntegration.protection.by', { user: protection.decided_by_username }) }}</span>
          </div>
          <p
            v-else
            class="text-muted"
          >
            {{ t('ciIntegration.protection.none') }}
          </p>
          <UAlert
            v-if="protection?.state === 'proposed' && detailText(protection, 'error')"
            color="warning"
            variant="subtle"
            :title="t('ciIntegration.protection.failed')"
            :description="detailText(protection, 'missing_permission') ? t('ciIntegration.missing', { permission: detailText(protection, 'missing_permission') }) : detailText(protection, 'error')"
          />
          <div class="flex flex-wrap gap-2">
            <template v-if="isAdmin && protection?.state === 'proposed'">
              <UButton
                icon="i-lucide-shield-check"
                :label="t('ciIntegration.protection.apply')"
                data-testid="ci-protection-apply"
                @click="askProtection('apply')"
              />
              <UButton
                variant="ghost"
                color="neutral"
                :label="t('ciIntegration.protection.decline')"
                @click="askProtection('decline')"
              />
            </template>
            <UButton
              v-if="isOperator && (!protection || protection.state === 'declined')"
              variant="soft"
              :loading="proposing"
              :label="t('ciIntegration.protection.propose')"
              @click="proposeAgain"
            />
          </div>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('ciIntegration.chain.title') }}
          </h2>
        </template>
        <div class="space-y-2 text-sm">
          <p class="text-muted">
            {{ t('ciIntegration.chain.help') }}
          </p>
          <USwitch
            :model-value="state.autonomous_chain"
            :disabled="!isAdmin || chainSaving"
            :loading="chainSaving"
            :label="t('ciIntegration.chain.label')"
            data-testid="ci-chain"
            @update:model-value="(v: boolean) => setChain(v)"
          />
        </div>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex items-center justify-between">
            <div>
              <h2 class="font-semibold">
                {{ t('ciIntegration.oidc.title') }}
              </h2>
              <p class="text-xs text-muted">
                {{ t('ciIntegration.oidc.help') }}
              </p>
            </div>
            <UButton
              v-if="isAdmin && state.issuers.length"
              icon="i-lucide-link"
              variant="soft"
              :label="t('ciIntegration.oidc.add')"
              @click="openBinding"
            />
          </div>
        </template>
        <ul
          v-if="state.bindings.length"
          class="divide-y divide-default text-sm"
        >
          <li
            v-for="b in state.bindings"
            :key="b.id"
            class="flex flex-wrap items-center justify-between gap-2 py-2"
          >
            <div>
              <code>{{ b.repository }}</code>
              <span class="text-xs text-muted"> · {{ b.issuer }}</span>
              <div class="text-xs text-muted">
                {{ b.ref_patterns.join(', ') }}
                · {{ b.repository_id ? t('ciIntegration.oidc.pinned', { id: b.repository_id }) : t('ciIntegration.oidc.notPinned') }}
              </div>
            </div>
            <div
              v-if="isAdmin"
              class="flex gap-1"
            >
              <UButton
                v-if="b.repository_id"
                size="xs"
                color="warning"
                variant="ghost"
                :label="t('ciIntegration.oidc.resetPin')"
                @click="askReset(b)"
              />
              <UButton
                size="xs"
                color="error"
                variant="ghost"
                :label="t('ciIntegration.oidc.remove')"
                @click="askRemove(b)"
              />
            </div>
          </li>
        </ul>
        <p
          v-else
          class="text-sm text-muted"
        >
          {{ t('ciIntegration.oidc.none') }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('ciIntegration.templates.title') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('ciIntegration.templates.help') }}
          </p>
        </template>
        <div class="flex flex-wrap gap-2">
          <UButton
            v-for="tpl in templates"
            :key="tpl.file"
            size="sm"
            variant="soft"
            icon="i-lucide-download"
            :to="templateUrl(tpl)"
            external
            download
            :label="tpl.label"
          />
        </div>
        <p
          v-if="state.client_sha256"
          class="mt-3 text-xs text-muted"
        >
          {{ t('ciIntegration.templates.digest') }} <code class="break-all">{{ state.client_sha256 }}</code>
        </p>
      </UCard>
    </template>

    <ConfirmModal
      v-model:open="protectOpen"
      :title="t(protectAction === 'apply' ? 'ciIntegration.protection.confirmApply' : 'ciIntegration.protection.confirmDecline')"
      :body="protectAction === 'apply' ? t('ciIntegration.protection.confirmBody', { repo: state?.repository ?? '', branch: state?.default_branch ?? '' }) : ''"
      :color="protectAction === 'apply' ? 'warning' : 'neutral'"
      :loading="deciding"
      :confirm-label="t(protectAction === 'apply' ? 'ciIntegration.protection.apply' : 'ciIntegration.protection.decline')"
      @confirm="decide"
    >
      <div
        v-if="protectAction === 'apply' && state"
        class="space-y-2 text-sm"
      >
        <p
          v-if="state.forge?.kind === 'gitlab'"
          data-testid="ci-protection-gitlab"
        >
          {{ t('ciIntegration.protection.gitlabRule') }}
        </p>
        <template v-else>
          <p class="font-medium">
            {{ t('ciIntegration.protection.rule') }}
          </p>
          <ul class="list-disc ps-5">
            <li
              v-for="c in ruleContexts"
              :key="c"
            >
              <code>{{ c }}</code>
            </li>
          </ul>
          <UCheckbox
            v-model="includeReleaseGate"
            :label="t('ciIntegration.protection.releaseGate')"
            :description="t('ciIntegration.protection.releaseGateHelp')"
          />
        </template>
      </div>
    </ConfirmModal>

    <UModal
      v-model:open="bindingOpen"
      :title="t('ciIntegration.oidc.add')"
      :dismissible="!bindingSaving"
    >
      <template #body>
        <div class="space-y-4">
          <UFormField :label="t('ciIntegration.oidc.issuer')">
            <USelect
              v-model="bindingForm.issuer_id"
              :items="issuerItems"
              class="w-full"
            />
          </UFormField>
          <UFormField :label="t('ciIntegration.oidc.repository')">
            <UInput
              v-model="bindingForm.repository"
              class="w-full"
            />
          </UFormField>
          <UFormField
            :label="t('ciIntegration.oidc.refs')"
            :help="t('ciIntegration.oidc.refsHelp')"
          >
            <UInput
              v-model="bindingForm.refs"
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
            :disabled="bindingSaving"
            @click="bindingOpen = false"
          />
          <UButton
            :loading="bindingSaving"
            :disabled="!bindingForm.issuer_id || !bindingForm.repository"
            :label="t('common.save')"
            @click="addBinding"
          />
        </div>
      </template>
    </UModal>

    <ConfirmModal
      v-model:open="resetOpen"
      :title="t('ciIntegration.oidc.resetTitle')"
      :body="t('ciIntegration.oidc.resetBody', { repo: removeTarget?.repository ?? '', id: removeTarget?.repository_id ?? '' })"
      color="warning"
      :loading="resetting"
      :confirm-label="t('ciIntegration.oidc.resetPin')"
      @confirm="resetPin"
    />

    <ConfirmModal
      v-model:open="removeOpen"
      :title="t('ciIntegration.oidc.removeTitle')"
      :body="t('ciIntegration.oidc.removeBody', { repo: removeTarget?.repository ?? '' })"
      color="error"
      :loading="removing"
      :confirm-label="t('ciIntegration.oidc.remove')"
      @confirm="removeBinding"
    />
  </div>
</template>
