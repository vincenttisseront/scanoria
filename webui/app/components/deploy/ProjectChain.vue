<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Déploiement après verdict favorable (0.8, J9, J11–J13, J16) : vue de la
chaîne du projet (PR analysées, fusion automatique de la forge, releases,
attestations, déploiements), cibles déclarées et cibles proposées depuis les
workflows du dépôt. L'appliance déclenche, propose ou promeut ; elle ne
déploie jamais elle-même et ne fusionne aucune PR.
-->

<script setup lang="ts">
const props = defineProps<{ projectId: string, isAdmin: boolean }>()

type Kind = 'cd-trigger' | 'gitops-pr' | 'registry-promotion'
interface Target {
  id: string
  kind: Kind
  environment: string
  on_trigger: 'release' | 'branch'
  config: Record<string, unknown>
  credential_hint: string | null
  auto_merge: boolean
  enabled: boolean
}
interface Deployment {
  id: string
  kind: Kind
  environment: string
  status: 'pending' | 'running' | 'succeeded' | 'failed' | 'refused'
  refused_reason: string | null
  external_url: string | null
  error: string | null
}
interface Attestation { id: string, subject_name: string, subject_digest: string, status: string, pushed_to: string | null, error: string | null }
interface Release {
  scan_id: string
  tag: string | null
  commit_sha: string | null
  verdict: string | null
  report_status: string | null
  reasons: unknown[]
  attestations: Attestation[]
  deployments: Deployment[]
}
interface Chain {
  autonomous: boolean
  pull_requests: { scan_id: string, number: number | null, verdict: string | null, auto_merge: string | null }[]
  releases: Release[]
}
interface Proposal { kind: 'cd-trigger', environment: string, config: Record<string, unknown>, reason: { workflow: string, path: string, inputs: string[] } }

const { t } = useI18n()
const { api, errorMessage } = useApi()
const toast = useToast()
const apiBase = computed(() => `/api/deploy/projects/${encodeURIComponent(props.projectId)}`)
const chain = ref<Chain | null>(null)
const targets = ref<Target[]>([])
const proposals = ref<Proposal[]>([])
const loading = ref(false)
const saving = ref(false)

async function load() {
  loading.value = true
  try {
    const [c, tg] = await Promise.all([api<Chain>(`${apiBase.value}/chain`), api<{ items: Target[] }>(`${apiBase.value}/targets`)])
    chain.value = c
    targets.value = tg.items
    if (props.isAdmin) proposals.value = (await api<{ items: Proposal[] }>(`${apiBase.value}/proposals`)).items
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}

let timer: ReturnType<typeof setInterval> | null = null
onMounted(() => {
  void load()
  // Rafraîchi sans recharger la page tant qu'une exécution est en cours.
  timer = setInterval(() => {
    if (chain.value?.releases.some(r => r.deployments.some(d => d.status === 'pending' || d.status === 'running'))) void load()
  }, 15_000)
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
})

const statusColor = (s: string) => (s === 'succeeded' || s === 'passed' || s === 'signed' || s === 'pushed' || s === 'enabled'
  ? 'success'
  : s === 'failed' || s === 'error' || s === 'refused' || s === 'inconclusive' ? 'error' : 'neutral')

function deploymentLabel(d: Deployment): string {
  const status = t(`deploy.status.${d.status}`)
  if (d.refused_reason) return `${status} : ${t(`deploy.refused.${d.refused_reason}`)}`
  return status
}

async function act(fn: () => Promise<unknown>, done: string) {
  saving.value = true
  try {
    await fn()
    toast.add({ title: t(done), color: 'success' })
    await load()
    return true
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
    return false
  }
  finally {
    saving.value = false
  }
}

function confirmProposal(p: Proposal) {
  void act(() => api(`${apiBase.value}/targets`, { method: 'POST', body: { kind: p.kind, environment: p.environment, on_trigger: 'release', config: p.config } }), 'deploy.created')
}

function toggle(target: Target) {
  void act(() => api(`/api/deploy/targets/${target.id}`, { method: 'PATCH', body: { enabled: !target.enabled } }), 'deploy.saved')
}

// Fusion automatique (J12) : action à risque, confirmée dans une modale.
const autoMergeTarget = ref<Target | null>(null)
const autoMergeOpen = computed({ get: () => !!autoMergeTarget.value, set: (v: boolean) => {
  if (!v) autoMergeTarget.value = null
} })
async function setAutoMerge() {
  const target = autoMergeTarget.value
  if (!target) return
  if (await act(() => api(`/api/deploy/targets/${target.id}`, { method: 'PATCH', body: { auto_merge: !target.auto_merge } }), 'deploy.saved')) autoMergeTarget.value = null
}

const removeTarget = ref<Target | null>(null)
const removeOpen = computed({ get: () => !!removeTarget.value, set: (v: boolean) => {
  if (!v) removeTarget.value = null
} })
async function remove() {
  const target = removeTarget.value
  if (!target) return
  if (await act(() => api(`/api/deploy/targets/${target.id}`, { method: 'DELETE' }), 'deploy.removed')) removeTarget.value = null
}

// Déclaration d'une cible.
const addOpen = ref(false)
const draft = reactive({
  kind: 'cd-trigger' as Kind, environment: 'production', on_trigger: 'release' as 'release' | 'branch', branch: 'main',
  provider: 'forge' as 'forge' | 'jenkins', workflow: 'deploy.yml', url: '', job: '',
  repo: '', base: 'main', path: '', image: '', source: '', destination: '', username: '', token: '',
})
const kindItems = computed(() => (['cd-trigger', 'gitops-pr', 'registry-promotion'] as const).map(k => ({ value: k, label: t(`deploy.kind.${k}`) })))
const triggerItems = computed(() => (['release', 'branch'] as const).map(k => ({ value: k, label: t(`deploy.trigger.${k}`) })))
const providerItems = computed(() => (['forge', 'jenkins'] as const).map(k => ({ value: k, label: t(`deploy.provider.${k}`) })))
const { repo: fRepo, base: fBase, path: fPath, image: fImage, source: fSource, destination: fDestination, username: fUsername, token: fToken } = toRefs(draft)
const isKind = (k: Kind) => draft.kind === k
const isProvider = (p: 'forge' | 'jenkins') => draft.provider === p
function configOf(): Record<string, unknown> {
  const branch = draft.on_trigger === 'branch' ? { branch: draft.branch.trim() } : {}
  if (draft.kind === 'cd-trigger') {
    return draft.provider === 'jenkins'
      ? { provider: 'jenkins', url: draft.url.trim(), job: draft.job.trim(), ...branch }
      : { provider: 'forge', workflow: draft.workflow.trim(), ...branch }
  }
  if (draft.kind === 'gitops-pr') return { repo: draft.repo.trim(), base: draft.base.trim(), files: [{ path: draft.path.trim(), image: draft.image.trim() }], ...branch }
  return { source: draft.source.trim(), destination: draft.destination.trim(), ...branch }
}
async function add() {
  const credential = draft.token ? { value: draft.token, ...(draft.username ? { username: draft.username } : {}) } : undefined
  const ok = await act(() => api(`${apiBase.value}/targets`, {
    method: 'POST',
    body: { kind: draft.kind, environment: draft.environment.trim(), on_trigger: draft.on_trigger, config: configOf(), ...(credential ? { credential } : {}) },
  }), 'deploy.created')
  if (ok) {
    addOpen.value = false
    draft.token = ''
  }
}
</script>

<template>
  <UCard data-testid="deploy-chain">
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="font-semibold">
            {{ t('deploy.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('deploy.help') }}
          </p>
        </div>
        <div class="flex gap-2">
          <UButton
            icon="i-lucide-refresh-cw"
            size="sm"
            color="neutral"
            variant="ghost"
            :loading="loading"
            :label="t('deploy.refresh')"
            @click="load"
          />
          <UButton
            v-if="isAdmin"
            icon="i-lucide-plus"
            size="sm"
            color="neutral"
            variant="subtle"
            :label="t('deploy.add')"
            data-testid="deploy-add"
            @click="addOpen = true"
          />
        </div>
      </div>
    </template>

    <div
      v-if="!chain"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <div
      v-else
      class="space-y-5 text-sm"
    >
      <UAlert
        v-if="chain.autonomous"
        icon="i-lucide-workflow"
        color="info"
        variant="subtle"
        :title="t('deploy.autonomous.title')"
        :description="t('deploy.autonomous.help')"
      />

      <section
        v-if="proposals.length"
        class="space-y-2"
      >
        <h3 class="font-medium">
          {{ t('deploy.proposals.title') }}
        </h3>
        <div
          v-for="p in proposals"
          :key="p.reason.path"
          class="flex flex-wrap items-center gap-2"
          data-testid="deploy-proposal"
        >
          <UIcon
            name="i-lucide-lightbulb"
            class="size-4"
          />
          <span>{{ t('deploy.proposals.why', { workflow: p.reason.path, environment: p.environment }) }}</span>
          <UButton
            size="xs"
            :loading="saving"
            :label="t('deploy.proposals.confirm')"
            @click="confirmProposal(p)"
          />
        </div>
      </section>

      <section class="space-y-2">
        <h3 class="font-medium">
          {{ t('deploy.targets.title') }}
        </h3>
        <p
          v-if="!targets.length"
          class="text-muted"
        >
          {{ t('deploy.targets.none') }}
        </p>
        <ul
          v-else
          class="space-y-1"
        >
          <li
            v-for="target in targets"
            :key="target.id"
            class="flex flex-wrap items-center gap-2"
          >
            <UBadge
              color="neutral"
              variant="subtle"
              :label="target.environment"
            />
            <span>{{ t(`deploy.kind.${target.kind}`) }}</span>
            <span class="text-muted">{{ t(`deploy.trigger.${target.on_trigger}`) }}</span>
            <UBadge
              v-if="!target.enabled"
              color="warning"
              variant="subtle"
              :label="t('deploy.targets.disabled')"
            />
            <UBadge
              v-if="target.auto_merge"
              color="info"
              variant="subtle"
              :label="t('deploy.targets.autoMerge')"
            />
            <template v-if="isAdmin">
              <UButton
                size="xs"
                color="neutral"
                variant="ghost"
                :loading="saving"
                :label="target.enabled ? t('deploy.targets.disable') : t('deploy.targets.enable')"
                @click="toggle(target)"
              />
              <UButton
                v-if="target.kind === 'gitops-pr'"
                size="xs"
                color="neutral"
                variant="ghost"
                :label="target.auto_merge ? t('deploy.targets.autoMergeOff') : t('deploy.targets.autoMergeOn')"
                @click="autoMergeTarget = target"
              />
              <UButton
                size="xs"
                color="error"
                variant="ghost"
                icon="i-lucide-trash-2"
                :label="t('deploy.targets.remove')"
                @click="removeTarget = target"
              />
            </template>
          </li>
        </ul>
      </section>

      <section
        v-if="chain.pull_requests.length"
        class="space-y-1"
      >
        <h3 class="font-medium">
          {{ t('deploy.prs.title') }}
        </h3>
        <div
          v-for="pr in chain.pull_requests"
          :key="pr.scan_id"
          class="flex flex-wrap items-center gap-2"
        >
          <NuxtLink
            :to="`/scans/${pr.scan_id}`"
            class="font-mono underline"
          >
            PR {{ pr.number }}
          </NuxtLink>
          <UBadge
            :color="statusColor(pr.verdict ?? 'pending')"
            variant="subtle"
            :label="pr.verdict ? t(`deploy.verdict.${pr.verdict}`) : t('deploy.status.pending')"
          />
          <span
            v-if="pr.auto_merge"
            class="text-muted"
          >{{ t(`deploy.autoMergeResult.${pr.auto_merge}`) }}</span>
        </div>
      </section>

      <section class="space-y-3">
        <h3 class="font-medium">
          {{ t('deploy.releases.title') }}
        </h3>
        <p
          v-if="!chain.releases.length"
          class="text-muted"
        >
          {{ t('deploy.releases.none') }}
        </p>
        <div
          v-for="r in chain.releases"
          :key="r.scan_id"
          class="space-y-1 border-l-2 border-default pl-3"
          data-testid="deploy-release"
        >
          <div class="flex flex-wrap items-center gap-2">
            <NuxtLink
              :to="`/scans/${r.scan_id}`"
              class="font-mono underline"
            >
              {{ r.tag ?? r.commit_sha?.slice(0, 12) }}
            </NuxtLink>
            <UBadge
              :color="statusColor(r.verdict ?? 'pending')"
              variant="subtle"
              :label="r.verdict ? t(`deploy.verdict.${r.verdict}`) : t('deploy.status.pending')"
            />
            <span
              v-if="r.report_status"
              class="text-muted"
            >{{ t(`deploy.report.${r.report_status}`) }}</span>
          </div>
          <p
            v-if="r.verdict && r.verdict !== 'passed'"
            class="text-error"
          >
            {{ t('deploy.releases.stopped', { count: r.reasons.length }) }}
          </p>
          <div
            v-for="a in r.attestations"
            :key="a.id"
            class="flex flex-wrap items-center gap-2"
          >
            <UIcon
              name="i-lucide-badge-check"
              class="size-4"
            />
            <span class="font-mono">{{ a.subject_name }}@{{ a.subject_digest.slice(0, 19) }}</span>
            <UBadge
              :color="statusColor(a.status)"
              variant="subtle"
              :label="t(`deploy.attestation.${a.status}`)"
            />
            <span
              v-if="a.status === 'signed' && a.error"
              class="text-warning"
            >{{ t('deploy.attestation.notPushed') }}</span>
            <a
              v-if="a.status === 'signed' || a.status === 'pushed'"
              :href="`/api/deploy/attestations/${a.id}`"
              class="underline"
            >{{ t('deploy.attestation.download') }}</a>
          </div>
          <div
            v-for="d in r.deployments"
            :key="d.id"
            class="flex flex-wrap items-center gap-2"
          >
            <UIcon
              :name="d.status === 'running' || d.status === 'pending' ? 'i-lucide-loader-circle' : 'i-lucide-rocket'"
              :class="['size-4', d.status === 'running' || d.status === 'pending' ? 'animate-spin' : '']"
            />
            <span>{{ d.environment }} · {{ t(`deploy.kind.${d.kind}`) }}</span>
            <UBadge
              :color="statusColor(d.status)"
              variant="subtle"
              :label="deploymentLabel(d)"
            />
            <a
              v-if="d.external_url"
              :href="d.external_url"
              target="_blank"
              rel="noopener noreferrer"
              class="underline"
            >{{ t('deploy.open') }}</a>
            <span
              v-if="d.error && d.status === 'failed'"
              class="font-mono text-muted"
            >{{ d.error }}</span>
          </div>
        </div>
      </section>
    </div>

    <ConfirmModal
      v-model:open="addOpen"
      :title="t('deploy.form.title')"
      :body="t('deploy.form.body')"
      :confirm-label="t('deploy.add')"
      :loading="saving"
      @confirm="add"
    >
      <div class="space-y-3">
        <UFormField :label="t('deploy.form.kind')">
          <USelect
            v-model="draft.kind"
            :items="kindItems"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('deploy.form.environment')">
          <UInput
            v-model="draft.environment"
            class="w-full font-mono"
          />
        </UFormField>
        <UFormField :label="t('deploy.form.trigger')">
          <USelect
            v-model="draft.on_trigger"
            :items="triggerItems"
            class="w-full"
          />
        </UFormField>
        <UFormField
          v-if="draft.on_trigger === 'branch'"
          :label="t('deploy.form.branch')"
        >
          <UInput
            v-model="draft.branch"
            class="w-full font-mono"
          />
        </UFormField>
        <template v-if="isKind('cd-trigger')">
          <UFormField :label="t('deploy.form.provider')">
            <USelect
              v-model="draft.provider"
              :items="providerItems"
              class="w-full"
            />
          </UFormField>
          <UFormField
            v-if="isProvider('forge')"
            :label="t('deploy.form.workflow')"
            :help="t('deploy.form.workflowHelp')"
          >
            <UInput
              v-model="draft.workflow"
              class="w-full font-mono"
            />
          </UFormField>
          <template v-else>
            <UFormField :label="t('deploy.form.jenkinsUrl')">
              <UInput
                v-model="draft.url"
                class="w-full font-mono"
                placeholder="https://jenkins.exemple.test"
              />
            </UFormField>
            <UFormField :label="t('deploy.form.job')">
              <UInput
                v-model="draft.job"
                class="w-full font-mono"
              />
            </UFormField>
          </template>
        </template>
        <template v-if="isKind('gitops-pr')">
          <UFormField :label="t('deploy.form.repo')">
            <UInput
              v-model="fRepo"
              class="w-full font-mono"
            />
          </UFormField>
          <UFormField :label="t('deploy.form.base')">
            <UInput
              v-model="fBase"
              class="w-full font-mono"
            />
          </UFormField>
          <UFormField :label="t('deploy.form.path')">
            <UInput
              v-model="fPath"
              class="w-full font-mono"
            />
          </UFormField>
          <UFormField :label="t('deploy.form.image')">
            <UInput
              v-model="fImage"
              class="w-full font-mono"
              placeholder="registre.exemple.test/equipe/app"
            />
          </UFormField>
        </template>
        <template v-if="isKind('registry-promotion')">
          <UFormField :label="t('deploy.form.source')">
            <UInput
              v-model="fSource"
              class="w-full font-mono"
              placeholder="registre.exemple.test/candidat/app"
            />
          </UFormField>
          <UFormField :label="t('deploy.form.destination')">
            <UInput
              v-model="fDestination"
              class="w-full font-mono"
              placeholder="registre.exemple.test/valide/app"
            />
          </UFormField>
        </template>
        <template v-if="isKind('registry-promotion') || (isKind('cd-trigger') && isProvider('jenkins'))">
          <UFormField :label="t('deploy.form.username')">
            <UInput
              v-model="fUsername"
              class="w-full"
              autocomplete="off"
            />
          </UFormField>
          <UFormField
            :label="t('deploy.form.token')"
            :help="t('deploy.form.tokenHelp')"
          >
            <UInput
              v-model="fToken"
              type="password"
              class="w-full"
              autocomplete="off"
            />
          </UFormField>
        </template>
      </div>
    </ConfirmModal>

    <ConfirmModal
      v-model:open="autoMergeOpen"
      color="warning"
      :title="autoMergeTarget?.auto_merge ? t('deploy.targets.autoMergeOff') : t('deploy.targets.autoMergeOn')"
      :body="t('deploy.targets.autoMergeBody')"
      :ack="autoMergeTarget?.auto_merge ? undefined : t('deploy.targets.autoMergeAck')"
      :loading="saving"
      @confirm="setAutoMerge"
    />
    <ConfirmModal
      v-model:open="removeOpen"
      color="error"
      :title="t('deploy.targets.removeTitle', { environment: removeTarget?.environment ?? '' })"
      :body="t('deploy.targets.removeBody')"
      :confirm-label="t('deploy.targets.remove')"
      :loading="saving"
      @confirm="remove"
    />
  </UCard>
</template>
