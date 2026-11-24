<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'un projet : source, ce qui a été décidé automatiquement et pourquoi
(détection F1, profil, gate, planification), réglages modifiables,
archivage, et suppression définitive confirmée en saisissant le slug.
-->

<script setup lang="ts">
import type { Project } from '~/composables/useProjects'

interface Detail {
  project: Project
  choices: { profiles: { id: string, slug: string }[], gates: { id: string, slug: string }[] }
  schedule: { daily_time_utc: string, last_daily_slot: string, poll_interval_s: number }
}

const route = useRoute()
const { t } = useI18n()
const session = useSession()
const fmt = useFormat()
const toast = useToast()
const { api, message, label, sourceLabel } = useProjects()

const detail = ref<Detail | null>(null)
const loadError = ref('')
const id = computed(() => String(route.params.id))
useHead({ title: computed(() => detail.value?.project.name ?? t('projects.title')) })

const form = reactive({ name: '', schedule: 'on-commit' as Project['schedule'], profile_id: '', gate_id: '', ai_opt_out: false, branches: '' })
function fill(p: Project) {
  Object.assign(form, {
    name: p.name, schedule: p.schedule, profile_id: p.profile_id, gate_id: p.gate_id, ai_opt_out: p.ai_opt_out,
    branches: p.tracked_branches.join(', '),
  })
}
async function load() {
  try {
    detail.value = await api<Detail>(`/api/projects/${id.value}`)
    fill(detail.value.project)
    loadError.value = ''
  }
  catch (err) {
    loadError.value = message(err)
  }
}
onMounted(load)

const project = computed(() => detail.value?.project ?? null)
const canEdit = computed(() => session.can('operator') && !!project.value && !project.value.archived_at)
const isAdmin = computed(() => canEdit.value && session.can('admin'))
const scheduleItems = computed(() => (['on-commit', 'daily', 'none'] as const).map(s => ({ label: label('schedule', s), value: s })))
const profileItems = computed(() => detail.value?.choices.profiles.map(p => ({ label: p.slug, value: p.id })) ?? [])
const gateItems = computed(() => detail.value?.choices.gates.map(g => ({ label: g.slug, value: g.id })) ?? [])
const scheduleWhy = computed(() => {
  const p = project.value
  if (!p || !detail.value) return ''
  if (p.schedule === 'on-commit' && p.source_kind === 'git' && (p.forge_id || p.repo_full_name)) {
    return t('projects.detail.whyOnCommit', { min: Math.round(detail.value.schedule.poll_interval_s / 60) })
  }
  if (p.schedule === 'none') return t('projects.detail.whyNone')
  return t('projects.detail.whyDaily', { time: detail.value.schedule.daily_time_utc })
})

const saving = ref(false)
async function save() {
  saving.value = true
  try {
    const branches = form.branches.split(/[\s,]+/).map(b => b.trim()).filter(Boolean)
    const res = await api<{ project: Project }>(`/api/projects/${id.value}`, {
      method: 'PATCH',
      body: {
        name: form.name.trim(), schedule: form.schedule, profile_id: form.profile_id,
        ...(form.gate_id !== detail.value?.project.gate_id ? { gate_id: form.gate_id } : {}),
        ai_opt_out: form.ai_opt_out, ...(branches.length ? { tracked_branches: branches } : {}),
      },
    })
    detail.value = { ...detail.value!, project: res.project }
    fill(res.project)
    toast.add({ title: t('projects.detail.saved'), color: 'success' })
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

const detecting = ref(false)
async function redetect() {
  detecting.value = true
  try {
    const res = await api<{ project: Project }>(`/api/projects/${id.value}/detect`, { method: 'POST' })
    detail.value = { ...detail.value!, project: res.project }
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    detecting.value = false
  }
}

const archiving = ref(false)
async function setArchived(archived: boolean) {
  archiving.value = true
  try {
    const res = await api<{ project: Project }>(`/api/projects/${id.value}/archive`, { method: 'POST', body: { archived } })
    detail.value = { ...detail.value!, project: res.project }
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    archiving.value = false
  }
}

const deleteOpen = ref(false)
const deleteConfirm = ref('')
const deleting = ref(false)
watch(deleteOpen, (open) => {
  if (open) deleteConfirm.value = ''
})
async function remove() {
  if (!project.value || deleteConfirm.value !== project.value.slug) return
  deleting.value = true
  try {
    await api(`/api/projects/${id.value}`, { method: 'DELETE', body: { confirm: deleteConfirm.value } })
    deleteOpen.value = false
    await navigateTo('/projects')
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    deleting.value = false
  }
}
</script>

<template>
  <PageShell :title="project?.name ?? t('projects.title')">
    <template #actions>
      <UButton
        to="/projects"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('projects.title')"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!project"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="project">
      <UAlert
        v-if="project.archived_at"
        color="neutral"
        variant="subtle"
        icon="i-lucide-archive"
        :title="t('projects.detail.archived', { date: fmt.date(project.archived_at) })"
      />

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('projects.detail.source') }}
          </h2>
        </template>
        <dl class="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_1fr]">
          <dt class="text-muted">
            {{ t('projects.sourceTitle') }}
          </dt>
          <dd class="font-mono text-xs">
            {{ sourceLabel(project) }}
          </dd>
          <template v-if="project.repo_url">
            <dt class="text-muted">
              {{ t('projects.detail.url') }}
            </dt>
            <dd class="font-mono text-xs">
              {{ project.repo_url }}
            </dd>
          </template>
          <dt class="text-muted">
            {{ t('projects.detail.credential') }}
          </dt>
          <dd>{{ project.has_credential ? `${label('credential', project.credential_kind ?? 'token')} ${project.credential_hint ?? ''}` : t('projects.detail.noCredential') }}</dd>
          <template v-if="project.ssh_known_hosts">
            <dt class="text-muted">
              {{ t('projects.detail.knownHosts') }}
            </dt>
            <dd class="font-mono text-xs break-all">
              {{ project.ssh_known_hosts }}
            </dd>
          </template>
          <dt class="text-muted">
            {{ t('projects.detail.lastCommit') }}
          </dt>
          <dd class="font-mono text-xs">
            {{ project.last_commit ? project.last_commit.slice(0, 12) : '—' }}
            <span v-if="project.last_polled_at"> · {{ t('projects.detail.polled', { date: fmt.date(project.last_polled_at) }) }}</span>
          </dd>
          <dt class="text-muted">
            {{ t('projects.lastScan') }}
          </dt>
          <dd>
            <template v-if="project.last_scan">
              #{{ project.last_scan.number }} · {{ project.last_scan.verdict ?? project.last_scan.status }} · {{ fmt.date(project.last_scan.queued_at) }}
            </template>
            <template v-else>
              {{ t('projects.noScan') }}
            </template>
          </dd>
        </dl>
      </UCard>

      <UCard>
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 class="font-semibold">
                {{ t('projects.detection.title') }}
              </h2>
              <p class="text-sm text-muted">
                {{ t('projects.detection.help') }}
              </p>
            </div>
            <UButton
              v-if="canEdit && project.source_kind === 'git'"
              icon="i-lucide-scan-search"
              color="neutral"
              variant="subtle"
              :loading="detecting"
              :label="t('projects.detection.rerun')"
              @click="redetect"
            />
          </div>
        </template>
        <p
          v-if="project.source_kind === 'archive'"
          class="text-sm text-muted"
        >
          {{ t('projects.detection.archive') }}
        </p>
        <ProjectDetection
          v-else
          :detection="project.detection"
          :can-install="session.can('admin')"
        />
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('projects.detail.settings') }}
          </h2>
          <p class="text-sm text-muted">
            {{ scheduleWhy }}
          </p>
        </template>
        <form
          class="grid gap-4 sm:grid-cols-2"
          @submit.prevent="save"
        >
          <UFormField :label="t('projects.name')">
            <UInput
              v-model="form.name"
              class="w-full"
              :disabled="!canEdit"
            />
          </UFormField>
          <UFormField :label="t('projects.scheduleTitle')">
            <USelect
              v-model="form.schedule"
              :items="scheduleItems"
              class="w-full"
              :disabled="!canEdit"
            />
          </UFormField>
          <UFormField
            :label="t('projects.detail.branches')"
            :help="t('projects.detail.branchesHelp')"
          >
            <UInput
              v-model="form.branches"
              class="w-full"
              :disabled="!canEdit || project.source_kind !== 'git'"
            />
          </UFormField>
          <UFormField :label="t('projects.detail.profile')">
            <USelect
              v-model="form.profile_id"
              :items="profileItems"
              class="w-full"
              :disabled="!canEdit"
            />
          </UFormField>
          <UFormField :label="t('projects.detail.gate')">
            <USelect
              v-model="form.gate_id"
              :items="gateItems"
              class="w-full"
              :disabled="!isAdmin"
            />
          </UFormField>
          <USwitch
            v-model="form.ai_opt_out"
            :disabled="!canEdit"
            :label="t('projects.detail.aiOptOut')"
            :description="t('projects.detail.aiOptOutHelp')"
          />
          <div
            v-if="canEdit"
            class="flex justify-end sm:col-span-2"
          >
            <UButton
              type="submit"
              :loading="saving"
              :label="t('common.save')"
            />
          </div>
        </form>
      </UCard>

      <UCard v-if="session.can('operator')">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm text-muted">
            {{ project.archived_at ? t('projects.detail.unarchiveHelp') : t('projects.detail.archiveHelp') }}
          </p>
          <div class="flex gap-2">
            <UButton
              :icon="project.archived_at ? 'i-lucide-archive-restore' : 'i-lucide-archive'"
              color="neutral"
              variant="subtle"
              :loading="archiving"
              :label="project.archived_at ? t('projects.detail.unarchive') : t('projects.detail.archive')"
              @click="setArchived(!project.archived_at)"
            />
            <UButton
              v-if="session.can('admin')"
              icon="i-lucide-trash-2"
              color="error"
              variant="ghost"
              :label="t('projects.detail.delete')"
              @click="deleteOpen = true"
            />
          </div>
        </div>
      </UCard>

      <ConfirmModal
        v-model:open="deleteOpen"
        color="error"
        :title="t('projects.detail.deleteTitle', { name: project.name })"
        :body="t('projects.detail.deleteBody')"
        :confirm-label="t('projects.detail.delete')"
        :loading="deleting"
        @confirm="remove"
      >
        <UFormField :label="t('projects.detail.deleteType', { slug: project.slug })">
          <UInput
            v-model="deleteConfirm"
            class="w-full font-mono"
            autocomplete="off"
          />
        </UFormField>
      </ConfirmModal>
    </template>
  </PageShell>
</template>
