<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Assistant d'ajout d'un projet (F1) : dépôt d'une forge connue (avec aperçu
de la détection), URL Git libre (jeton HTTPS, ou clé SSH et clés d'hôte
relevées puis confirmées), ou archive téléversée. Profil, gate et
planification sont choisis automatiquement et modifiables ensuite.
-->

<script setup lang="ts">
import type { Forge, ForgeRepo, Project, ProjectDetection } from '~/composables/useProjects'

definePageMeta({ role: 'operator' })
const { t } = useI18n()
useHead({ title: computed(() => t('projects.new.title')) })
const session = useSession()
const { api, message } = useProjects()

type Mode = 'forge' | 'git' | 'archive'
const mode = ref<Mode>('forge')
const modes = computed(() => [
  { label: t('projects.new.fromForge'), value: 'forge' },
  { label: t('projects.new.fromUrl'), value: 'git' },
  { label: t('projects.new.fromArchive'), value: 'archive' },
])
const error = ref('')
function setMode(m: Mode) {
  mode.value = m
  error.value = ''
}
const saving = ref(false)

async function created(body: Record<string, unknown>) {
  saving.value = true
  error.value = ''
  try {
    const res = await api<{ project: Project }>('/api/projects', { method: 'POST', body })
    await navigateTo(`/projects/${res.project.id}`)
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    saving.value = false
  }
}

// --- Depuis une forge ---
const forges = ref<Forge[]>([])
const forgeId = ref<string | undefined>(undefined)
const repos = ref<ForgeRepo[] | null>(null)
const reposLoading = ref(false)
const repoFilter = ref('')
const selected = ref<ForgeRepo | null>(null)
const preview = ref<{ detection: ProjectDetection, branches: string[] } | null>(null)
const previewing = ref(false)

onMounted(async () => {
  try {
    forges.value = (await api<{ items: Forge[] }>('/api/forges')).items
    if (forges.value.length) forgeId.value = forges.value[0]!.id
    else mode.value = 'git'
  }
  catch (err) {
    error.value = message(err)
  }
})
watch(forgeId, async (id) => {
  repos.value = null
  selected.value = null
  preview.value = null
  if (!id) return
  reposLoading.value = true
  try {
    repos.value = (await api<{ items: ForgeRepo[] }>(`/api/forges/${id}/repos`)).items
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    reposLoading.value = false
  }
})
const forgeItems = computed(() => forges.value.map(f => ({ label: f.name, value: f.id })))
const shownRepos = computed(() => {
  const q = repoFilter.value.trim().toLowerCase()
  return (repos.value ?? []).filter(r => !q || r.full_name.toLowerCase().includes(q)).slice(0, 200)
})

async function pick(r: ForgeRepo) {
  selected.value = r
  preview.value = null
  previewing.value = true
  error.value = ''
  try {
    preview.value = await api('/api/projects/preview', { method: 'POST', body: { forge_id: forgeId.value!, repo: r.full_name } })
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    previewing.value = false
  }
}

// --- URL Git libre ---
const git = reactive({ url: '', auth: 'none' as 'none' | 'token' | 'ssh-key', token: '', username: '', privateKey: '', branch: '' })
const isSsh = computed(() => /^(ssh:\/\/|[A-Za-z0-9._-]+@[^:/]+:)/.test(git.url.trim()))
const authItems = computed(() => [
  { label: t('projects.new.authNone'), value: 'none' },
  { label: t('projects.new.authToken'), value: 'token' },
  { label: t('projects.new.authSsh'), value: 'ssh-key' },
])
watch(isSsh, (ssh) => {
  if (ssh) git.auth = 'ssh-key'
  else if (git.auth === 'ssh-key') git.auth = 'none'
})
const hostKeys = ref<{ host: string, keys: { type: string, fingerprint: string }[], known_hosts: string } | null>(null)
const scanning = ref(false)
const keysConfirmed = ref(false)
async function scanKeys() {
  scanning.value = true
  hostKeys.value = null
  keysConfirmed.value = false
  error.value = ''
  try {
    hostKeys.value = await api('/api/projects/ssh-hostkeys', { method: 'POST', body: { url: git.url.trim() } })
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    scanning.value = false
  }
}
const canAddGit = computed(() => {
  if (!git.url.trim()) return false
  if (git.auth === 'token') return !!git.token
  if (git.auth === 'ssh-key') return !!git.privateKey && !!hostKeys.value && keysConfirmed.value
  return true
})
function addGit() {
  const auth = git.auth === 'token'
    ? { kind: 'token', token: git.token, ...(git.username ? { username: git.username } : {}) }
    : git.auth === 'ssh-key'
      ? { kind: 'ssh-key', private_key: git.privateKey.replace(/\r\n/g, '\n').trimEnd() + '\n', known_hosts: hostKeys.value!.known_hosts }
      : { kind: 'none' }
  return created({ source: 'git', url: git.url.trim(), auth, ...(git.branch ? { default_branch: git.branch.trim() } : {}) })
}

// --- Archive ---
const archiveName = ref('')
const archiveFile = ref<File | null>(null)
const uploading = ref(false)
function onFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0] ?? null
  archiveFile.value = f
  if (f && !archiveName.value) archiveName.value = f.name.replace(/\.(zip|tar|tar\.gz|tgz)$/i, '')
}
async function addArchive() {
  if (!archiveFile.value) return
  uploading.value = true
  error.value = ''
  try {
    const up = await api<{ upload_id: string }>('/api/projects/uploads', {
      method: 'PUT', body: archiveFile.value, headers: { 'content-type': 'application/octet-stream' },
    })
    uploading.value = false
    await created({ source: 'archive', upload_id: up.upload_id, name: archiveName.value.trim() })
  }
  catch (err) {
    error.value = message(err)
  }
  finally {
    uploading.value = false
  }
}
</script>

<template>
  <PageShell :title="t('projects.new.title')">
    <template #actions>
      <UButton
        to="/projects"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('projects.title')"
      />
    </template>

    <p class="text-sm text-muted">
      {{ t('projects.new.help') }}
    </p>

    <div
      class="flex flex-wrap gap-2"
      role="tablist"
    >
      <UButton
        v-for="m in modes"
        :key="m.value"
        role="tab"
        :aria-selected="mode === m.value"
        :color="mode === m.value ? 'primary' : 'neutral'"
        :variant="mode === m.value ? 'solid' : 'subtle'"
        :label="m.label"
        @click="setMode(m.value as Mode)"
      />
    </div>

    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      :title="error"
    />

    <!-- Depuis une forge -->
    <template v-if="mode === 'forge'">
      <UCard v-if="!forges.length">
        <p class="text-sm text-muted">
          {{ t('projects.new.noForge') }}
        </p>
        <UButton
          v-if="session.can('admin')"
          to="/projects/forges"
          class="mt-3"
          icon="i-lucide-plug"
          :label="t('projects.forges.addTitle')"
        />
      </UCard>
      <UCard v-else>
        <div class="flex flex-wrap items-end gap-3">
          <UFormField :label="t('projects.new.forge')">
            <USelect
              v-model="forgeId"
              :items="forgeItems"
              class="w-64"
            />
          </UFormField>
          <UInput
            v-model="repoFilter"
            icon="i-lucide-search"
            :placeholder="t('projects.filter')"
            class="w-72"
          />
        </div>
        <div
          v-if="reposLoading"
          class="mt-3 flex items-center gap-2 text-sm text-muted"
          role="status"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-4 animate-spin"
          />
          {{ t('projects.new.loadingRepos') }}
        </div>
        <ul
          v-else-if="repos"
          class="mt-3 max-h-80 divide-y divide-default overflow-y-auto text-sm"
        >
          <li
            v-for="r in shownRepos"
            :key="r.full_name"
            class="flex items-center justify-between gap-2 py-1.5"
          >
            <span>
              <span class="font-mono">{{ r.full_name }}</span>
              <span
                v-if="r.private"
                class="ml-2 text-xs text-muted"
              >{{ t('projects.new.private') }}</span>
            </span>
            <NuxtLink
              v-if="r.project_id"
              :to="`/projects/${r.project_id}`"
              class="text-xs text-primary hover:underline"
            >{{ t('projects.new.alreadyProject') }}</NuxtLink>
            <UButton
              v-else
              size="xs"
              color="neutral"
              variant="subtle"
              :disabled="r.empty || r.archived"
              :loading="previewing && selected?.full_name === r.full_name"
              :label="t('projects.new.choose')"
              @click="pick(r)"
            />
          </li>
          <li
            v-if="!shownRepos.length"
            class="py-2 text-muted"
          >
            {{ t('projects.new.noRepo') }}
          </li>
        </ul>
      </UCard>

      <UCard v-if="selected && (preview || previewing)">
        <template #header>
          <h2 class="font-semibold">
            {{ t('projects.new.previewTitle', { repo: selected.full_name }) }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('projects.new.previewHelp') }}
          </p>
        </template>
        <div
          v-if="previewing"
          class="flex items-center gap-2 text-sm text-muted"
          role="status"
        >
          <UIcon
            name="i-lucide-loader-circle"
            class="size-4 animate-spin"
          />
          {{ t('projects.new.detecting') }}
        </div>
        <ProjectDetection
          v-else
          :detection="preview!.detection"
          :can-install="session.can('admin')"
        />
        <template #footer>
          <div class="flex justify-end">
            <UButton
              icon="i-lucide-plus"
              :loading="saving"
              :disabled="previewing"
              :label="t('projects.new.addButton')"
              @click="created({ source: 'forge', forge_id: forgeId, repo: selected.full_name })"
            />
          </div>
        </template>
      </UCard>
    </template>

    <!-- URL Git libre -->
    <UCard v-else-if="mode === 'git'">
      <form
        class="space-y-4"
        @submit.prevent="addGit"
      >
        <UFormField
          :label="t('projects.new.url')"
          :help="t('projects.new.urlHelp')"
        >
          <UInput
            v-model="git.url"
            class="w-full"
            placeholder="https://git.exemple.test/equipe/depot.git"
          />
        </UFormField>
        <UFormField :label="t('projects.new.auth')">
          <USelect
            v-model="git.auth"
            :items="isSsh ? authItems.filter(a => a.value === 'ssh-key') : authItems.filter(a => a.value !== 'ssh-key')"
            class="w-64"
          />
        </UFormField>
        <template v-if="git.auth === 'token'">
          <UFormField :label="t('projects.new.token')">
            <UInput
              v-model="git.token"
              type="password"
              autocomplete="off"
              class="w-full"
            />
          </UFormField>
          <UFormField
            :label="t('projects.new.username')"
            :help="t('projects.new.usernameHelp')"
          >
            <UInput
              v-model="git.username"
              autocomplete="off"
              class="w-64"
            />
          </UFormField>
        </template>
        <template v-if="git.auth === 'ssh-key'">
          <UFormField
            :label="t('projects.new.privateKey')"
            :help="t('projects.new.privateKeyHelp')"
          >
            <UTextarea
              v-model="git.privateKey"
              :rows="5"
              autocomplete="off"
              class="w-full font-mono"
            />
          </UFormField>
          <div class="space-y-2">
            <UButton
              icon="i-lucide-fingerprint"
              color="neutral"
              variant="subtle"
              :loading="scanning"
              :disabled="!git.url"
              :label="t('projects.new.scanKeys')"
              @click="scanKeys"
            />
            <div
              v-if="hostKeys"
              class="space-y-2 rounded border border-default p-3 text-sm"
            >
              <p>{{ t('projects.new.keysFor', { host: hostKeys.host }) }}</p>
              <ul class="font-mono text-xs">
                <li
                  v-for="k in hostKeys.keys"
                  :key="k.fingerprint"
                >
                  {{ k.type }} {{ k.fingerprint }}
                </li>
              </ul>
              <UCheckbox
                v-model="keysConfirmed"
                :label="t('projects.new.keysConfirm')"
              />
            </div>
          </div>
        </template>
        <UFormField
          :label="t('projects.new.branch')"
          :help="t('projects.new.branchHelp')"
        >
          <UInput
            v-model="git.branch"
            class="w-64"
            placeholder="main"
          />
        </UFormField>
        <div class="flex justify-end">
          <UButton
            type="submit"
            icon="i-lucide-plus"
            :loading="saving"
            :disabled="!canAddGit"
            :label="t('projects.new.addButton')"
          />
        </div>
      </form>
    </UCard>

    <!-- Archive -->
    <UCard v-else>
      <form
        class="space-y-4"
        @submit.prevent="addArchive"
      >
        <div class="space-y-1">
          <label
            for="project-archive-file"
            class="block text-sm font-medium"
          >{{ t('projects.new.archiveFile') }}</label>
          <input
            id="project-archive-file"
            type="file"
            accept=".zip,.tar,.tar.gz,.tgz,application/zip,application/x-tar,application/gzip"
            class="text-sm"
            aria-describedby="project-archive-help"
            @change="onFile"
          >
          <p
            id="project-archive-help"
            class="text-sm text-muted"
          >
            {{ t('projects.new.archiveHelp') }}
          </p>
        </div>
        <UFormField :label="t('projects.name')">
          <UInput
            v-model="archiveName"
            class="w-full"
            maxlength="200"
          />
        </UFormField>
        <div class="flex justify-end">
          <UButton
            type="submit"
            icon="i-lucide-upload"
            :loading="uploading || saving"
            :disabled="!archiveFile || !archiveName.trim()"
            :label="uploading ? t('projects.new.uploading') : t('projects.new.addButton')"
          />
        </div>
      </form>
    </UCard>
  </PageShell>
</template>
