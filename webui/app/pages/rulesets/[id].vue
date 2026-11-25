<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Jeu de règles (G4) : nouvelle version (édition), validation par le moteur
dans le conteneur confiné du module, historique avec écart et retour
arrière (nouvelle version), rattachement aux profils (dernière version ou
version épinglée), archivage. Toutes les confirmations sont des modales.
-->

<script setup lang="ts">
const { t } = useI18n()
const route = useRoute()
const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()
const isAdmin = computed(() => session.can('admin'))
const validation = useHelperRequest()

type Engine = 'opengrep' | 'semgrep' | 'gitleaks' | 'checkov' | 'kics'
interface Ruleset {
  id: string
  slug: string
  engine: Engine
  name: string
  description: string | null
  archived_at: string | null
  latest_version: number | null
}
interface Version {
  version: number
  sha256: string
  comment: string | null
  origin: 'manual' | 'import' | 'ai'
  created_by_name: string | null
  created_at: string
  bytes: number
}
interface Attachment { profile_id: string, profile_slug: string, pinned_version: number | null }
interface Profile { id: string, slug: string, builtin: boolean }
interface DiffLine { op: ' ' | '+' | '-', text: string }

const id = computed(() => String(route.params.id))
const ruleset = ref<Ruleset | null>(null)
const versions = ref<Version[]>([])
const attachments = ref<Attachment[]>([])
const profiles = ref<Profile[]>([])
const loading = ref(false)
useHead({ title: computed(() => ruleset.value?.name ?? t('rulesets.title')) })

const content = ref('')
const comment = ref('')
const saving = ref(false)

async function load() {
  loading.value = true
  try {
    const r = await api<{ ruleset: Ruleset, versions: Version[], attachments: Attachment[], profiles: Profile[] }>(`/api/rulesets/${id.value}`)
    ruleset.value = r.ruleset
    versions.value = r.versions
    attachments.value = r.attachments
    profiles.value = r.profiles
    draft.value = r.attachments.map(a => ({ ...a }))
    if (r.ruleset.latest_version) {
      const v = await api<{ content: string }>(`/api/rulesets/${id.value}/versions/${r.ruleset.latest_version}`)
      content.value = v.content
    }
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

async function saveVersion() {
  saving.value = true
  try {
    const r = await api<{ version: number }>(`/api/rulesets/${id.value}/versions`, {
      method: 'POST', body: { content: content.value, comment: comment.value.trim() || null },
    })
    toast.add({ title: t('rulesets.detail.saved', { version: r.version }), color: 'success' })
    comment.value = ''
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

// ------------------------------------------------------------ validation
const samples = ref<{ name: string, content: string }[]>([])
const SAMPLE_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$/
const samplesValid = computed(() => samples.value.every(s => SAMPLE_RE.test(s.name) && s.content.length <= 8192)
  && new Set(samples.value.map(s => s.name)).size === samples.value.length)
interface ValidationOutput { ok: boolean, module: string, version: string, errors: string[], samples: { name: string, matches: number }[] }
const output = computed(() => validation.result.value?.status === 'ok' ? validation.result.value.output as unknown as ValidationOutput : null)

async function validate() {
  if (!ruleset.value) return
  await validation.run('/api/rulesets/validate', { engine: ruleset.value.engine, content: content.value, samples: samples.value, ruleset_id: id.value }, { timeoutMs: 10 * 60_000 })
}

// ------------------------------------------------------------ historique
const shown = ref<{ version: number, content: string, diff: DiffLine[] | null, mode: 'view' | 'diff' } | null>(null)
const shownOpen = computed({ get: () => shown.value !== null, set: (v) => {
  if (!v) shown.value = null
} })
async function show(v: Version, mode: 'view' | 'diff') {
  try {
    const r = await api<{ content: string, diff?: DiffLine[] | null }>(`/api/rulesets/${id.value}/versions/${v.version}`,
      { query: mode === 'diff' ? { diff: v.version - 1 } : {} })
    shown.value = { version: v.version, content: r.content, diff: r.diff ?? null, mode }
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
}

const rollbackTarget = ref<number | null>(null)
const rollbackOpen = computed({ get: () => rollbackTarget.value !== null, set: (v) => {
  if (!v) rollbackTarget.value = null
} })
const rollingBack = ref(false)
async function rollback() {
  rollingBack.value = true
  try {
    const r = await api<{ version: number }>(`/api/rulesets/${id.value}/rollback`, { method: 'POST', body: { version: rollbackTarget.value } })
    toast.add({ title: t('rulesets.detail.rolledBack', { version: r.version }), color: 'success' })
    rollbackTarget.value = null
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    rollingBack.value = false
  }
}

// ------------------------------------------------------------ profils
const draft = ref<Attachment[]>([])
const savingProfiles = ref(false)
const addable = computed(() => profiles.value.filter(p => !draft.value.some(d => d.profile_id === p.id))
  .map(p => ({ label: p.slug, value: p.id })))
const versionItems = computed(() => [
  { label: t('rulesets.profiles.latest'), value: 'latest' },
  ...versions.value.map(v => ({ label: t('rulesets.profiles.pinned', { version: v.version }), value: String(v.version) })),
])
const profilesDirty = computed(() => JSON.stringify(draft.value.map(d => [d.profile_id, d.pinned_version]))
  !== JSON.stringify(attachments.value.map(d => [d.profile_id, d.pinned_version])))
function addProfile(pid: string) {
  const p = profiles.value.find(x => x.id === pid)
  if (p) draft.value.push({ profile_id: p.id, profile_slug: p.slug, pinned_version: null })
}
function setPinned(a: Attachment, v: string) {
  a.pinned_version = v === 'latest' ? null : Number(v)
}
async function saveProfiles() {
  savingProfiles.value = true
  try {
    await api(`/api/rulesets/${id.value}/profiles`, {
      method: 'PUT', body: { profiles: draft.value.map(d => ({ profile_id: d.profile_id, pinned_version: d.pinned_version })) },
    })
    toast.add({ title: t('rulesets.profiles.saved'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    savingProfiles.value = false
  }
}

// ------------------------------------------------------------ archivage
const archiveOpen = ref(false)
const archiving = ref(false)
async function setArchived(archived: boolean) {
  archiving.value = true
  try {
    await api(`/api/rulesets/${id.value}`, { method: 'PATCH', body: { archived } })
    toast.add({ title: t(archived ? 'rulesets.detail.archivedDone' : 'rulesets.detail.unarchivedDone'), color: 'success' })
    archiveOpen.value = false
    await load()
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    archiving.value = false
  }
}
</script>

<template>
  <PageShell :title="ruleset?.name ?? t('rulesets.title')">
    <template #actions>
      <UButton
        to="/rulesets"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('rulesets.detail.back')"
      />
      <UButton
        v-if="isAdmin && ruleset"
        color="neutral"
        variant="outline"
        :icon="ruleset.archived_at ? 'i-lucide-archive-restore' : 'i-lucide-archive'"
        :label="ruleset.archived_at ? t('rulesets.detail.unarchive') : t('rulesets.detail.archive')"
        :loading="archiving"
        data-testid="ruleset-archive"
        @click="ruleset.archived_at ? setArchived(false) : (archiveOpen = true)"
      />
    </template>

    <div
      v-if="loading && !ruleset"
      class="flex justify-center py-6"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-6 animate-spin"
      />
    </div>

    <template v-if="ruleset">
      <p class="text-sm text-muted">
        <span class="font-mono">{{ ruleset.slug }}</span> · {{ t(`rulesets.engines.${ruleset.engine}`) }}
        <template v-if="ruleset.description">
          · {{ ruleset.description }}
        </template>
      </p>
      <UAlert
        v-if="ruleset.archived_at"
        color="neutral"
        variant="subtle"
        icon="i-lucide-archive"
        :title="t('rulesets.archived')"
      />

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('rulesets.detail.edit') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('rulesets.detail.editHelp') }} {{ t(`rulesets.formats.${ruleset.engine}`) }}
          </p>
        </template>
        <div class="space-y-3">
          <UTextarea
            v-model="content"
            :rows="16"
            :disabled="!isAdmin || !!ruleset.archived_at"
            class="w-full font-mono text-xs"
            data-testid="ruleset-editor"
          />
          <div
            v-if="isAdmin && !ruleset.archived_at"
            class="flex flex-wrap items-end gap-2"
          >
            <UFormField
              :label="t('rulesets.create.comment')"
              class="min-w-64 flex-1"
            >
              <UInput
                v-model="comment"
                class="w-full"
              />
            </UFormField>
            <UButton
              icon="i-lucide-save"
              :label="t('common.save')"
              :loading="saving"
              :disabled="!content.trim()"
              data-testid="ruleset-save"
              @click="saveVersion"
            />
          </div>
        </div>
      </UCard>

      <UCard v-if="isAdmin">
        <template #header>
          <h2 class="font-semibold">
            {{ t('rulesets.validate.title') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('rulesets.validate.help') }} {{ t('rulesets.validate.needsModule') }}
          </p>
        </template>
        <div class="space-y-3">
          <p class="text-sm font-medium">
            {{ t('rulesets.validate.samples') }}
          </p>
          <div
            v-for="(s, i) in samples"
            :key="i"
            class="space-y-2 rounded-md border border-default p-3"
          >
            <div class="flex items-end gap-2">
              <UFormField
                :label="t('rulesets.validate.sampleName')"
                class="flex-1"
              >
                <UInput
                  v-model="s.name"
                  class="w-full font-mono"
                  placeholder="app.py"
                />
              </UFormField>
              <UButton
                color="neutral"
                variant="ghost"
                icon="i-lucide-trash-2"
                :aria-label="t('rulesets.validate.removeSample')"
                @click="samples.splice(i, 1)"
              />
            </div>
            <UTextarea
              v-model="s.content"
              :rows="5"
              class="w-full font-mono text-xs"
              :maxlength="8192"
            />
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <UButton
              color="neutral"
              variant="outline"
              icon="i-lucide-plus"
              :label="t('rulesets.validate.addSample')"
              :disabled="samples.length >= 10"
              @click="samples.push({ name: '', content: '' })"
            />
            <UButton
              icon="i-lucide-flask-conical"
              :label="t('rulesets.validate.action')"
              :loading="validation.running.value"
              :disabled="!content.trim() || !samplesValid"
              data-testid="ruleset-validate"
              @click="validate"
            />
            <RequestProgress
              :active="validation.running.value"
              :label="validation.label.value"
            />
          </div>
          <div
            v-if="output"
            data-testid="ruleset-validation"
          >
            <UAlert
              :color="output.ok ? 'success' : 'error'"
              :icon="output.ok ? 'i-lucide-circle-check' : 'i-lucide-circle-x'"
              :title="output.ok ? t('rulesets.validate.ok', { module: output.module, version: output.version }) : t('rulesets.validate.invalid')"
            >
              <template
                v-if="output.errors.length"
                #description
              >
                <pre class="whitespace-pre-wrap text-xs">{{ output.errors.join('\n') }}</pre>
              </template>
            </UAlert>
            <ul
              v-if="output.samples.length"
              class="mt-2 space-y-1 text-sm"
            >
              <li
                v-for="s in output.samples"
                :key="s.name"
              >
                <span class="font-mono">{{ s.name }}</span> : {{ t('rulesets.validate.matches', { n: s.matches }) }}
              </li>
            </ul>
          </div>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('rulesets.profiles.title') }}
          </h2>
          <p class="text-xs text-muted">
            {{ t('rulesets.profiles.help') }}
          </p>
        </template>
        <p
          v-if="!draft.length"
          class="text-sm text-muted"
        >
          {{ t('rulesets.profiles.none') }}
        </p>
        <table
          v-else
          class="w-full text-sm"
        >
          <thead class="sr-only">
            <tr>
              <th scope="col">
                {{ t('rulesets.profiles.profile') }}
              </th>
              <th scope="col">
                {{ t('rulesets.profiles.version') }}
              </th>
              <th scope="col">
                {{ t('rulesets.columns.actions') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(a, i) in draft"
              :key="a.profile_id"
              class="border-t border-default first:border-t-0"
            >
              <td class="py-2 font-mono">
                {{ a.profile_slug }}
              </td>
              <td class="py-2">
                <USelect
                  v-if="isAdmin"
                  :model-value="a.pinned_version === null ? 'latest' : String(a.pinned_version)"
                  :items="versionItems"
                  class="w-48"
                  @update:model-value="(v: string) => setPinned(a, v)"
                />
                <span v-else>{{ a.pinned_version === null ? t('rulesets.profiles.latest') : t('rulesets.profiles.pinned', { version: a.pinned_version }) }}</span>
              </td>
              <td class="py-2 text-right">
                <UButton
                  v-if="isAdmin"
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-x"
                  :label="t('rulesets.profiles.remove')"
                  @click="draft.splice(i, 1)"
                />
              </td>
            </tr>
          </tbody>
        </table>
        <div
          v-if="isAdmin && !ruleset.archived_at"
          class="mt-3 flex flex-wrap items-center gap-2"
        >
          <USelect
            v-if="addable.length && versions.length"
            :items="addable"
            :placeholder="t('rulesets.profiles.add')"
            class="w-56"
            data-testid="ruleset-add-profile"
            @update:model-value="(v: string) => addProfile(v)"
          />
          <UButton
            :label="t('common.save')"
            :loading="savingProfiles"
            :disabled="!profilesDirty"
            data-testid="ruleset-profiles-save"
            @click="saveProfiles"
          />
        </div>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('rulesets.detail.history') }}
          </h2>
        </template>
        <table class="w-full text-sm">
          <thead class="sr-only">
            <tr>
              <th scope="col">
                {{ t('rulesets.detail.version') }}
              </th>
              <th scope="col">
                {{ t('rulesets.columns.details') }}
              </th>
              <th scope="col">
                {{ t('rulesets.columns.actions') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="v in versions"
              :key="v.version"
              class="border-t border-default first:border-t-0"
              :data-testid="`ruleset-version-${v.version}`"
            >
              <td class="py-2 font-medium">
                {{ t('rulesets.latest', { version: v.version }) }}
              </td>
              <td class="py-2 text-xs text-muted">
                {{ fmt.date(v.created_at) }}
                <template v-if="v.created_by_name">
                  · {{ t('rulesets.detail.by', { user: v.created_by_name }) }}
                </template>
                · {{ t(`rulesets.origins.${v.origin}`) }} · {{ t('rulesets.detail.bytes', { n: v.bytes }) }}
                <span class="font-mono">· {{ v.sha256.slice(0, 12) }}</span>
                <div v-if="v.comment">
                  {{ v.comment }}
                </div>
              </td>
              <td class="py-2 text-right whitespace-nowrap">
                <UButton
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-eye"
                  :label="t('rulesets.detail.view')"
                  @click="show(v, 'view')"
                />
                <UButton
                  v-if="v.version > 1"
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-git-compare"
                  :label="t('rulesets.detail.diff')"
                  @click="show(v, 'diff')"
                />
                <UButton
                  v-if="isAdmin && !ruleset.archived_at && v.version !== ruleset.latest_version"
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-undo-2"
                  :label="t('rulesets.detail.rollback')"
                  :data-testid="`ruleset-rollback-${v.version}`"
                  @click="rollbackTarget = v.version"
                />
              </td>
            </tr>
          </tbody>
        </table>
      </UCard>
    </template>

    <UModal
      v-model:open="shownOpen"
      :title="shown ? t('rulesets.latest', { version: shown.version }) : ''"
      :ui="{ content: 'max-w-4xl' }"
    >
      <template #body>
        <template v-if="shown?.mode === 'diff'">
          <p
            v-if="!shown.diff"
            class="text-sm text-muted"
          >
            {{ t('rulesets.detail.diffTooLarge') }}
          </p>
          <pre
            v-else
            class="max-h-[60vh] overflow-auto rounded-md bg-elevated p-3 text-xs"
            data-testid="ruleset-diff"
          ><span
            v-for="(l, i) in shown.diff"
            :key="i"
            :class="l.op === '+' ? 'text-success' : l.op === '-' ? 'text-error' : 'text-muted'"
          >{{ l.op }} {{ l.text }}
</span></pre>
        </template>
        <pre
          v-else
          class="max-h-[60vh] overflow-auto rounded-md bg-elevated p-3 text-xs"
        ><code>{{ shown?.content }}</code></pre>
      </template>
    </UModal>

    <UModal
      v-model:open="rollbackOpen"
      :title="t('rulesets.detail.rollbackTitle', { version: rollbackTarget ?? 0 })"
      :dismissible="!rollingBack"
    >
      <template #body>
        <p class="text-sm">
          {{ t('rulesets.detail.rollbackBody', { version: rollbackTarget ?? 0 }) }}
        </p>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="rollingBack"
            :label="t('common.cancel')"
            @click="rollbackTarget = null"
          />
          <UButton
            :loading="rollingBack"
            :label="t('common.confirm')"
            data-testid="ruleset-rollback-confirm"
            @click="rollback"
          />
        </div>
      </template>
    </UModal>

    <UModal
      v-model:open="archiveOpen"
      :title="t('rulesets.detail.archiveTitle')"
      :dismissible="!archiving"
    >
      <template #body>
        <p class="text-sm">
          {{ attachments.length ? t('rulesets.detail.archiveAttached') : t('rulesets.detail.archiveBody') }}
        </p>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="archiving"
            :label="t('common.cancel')"
            @click="archiveOpen = false"
          />
          <UButton
            color="warning"
            :loading="archiving"
            :disabled="attachments.length > 0"
            :label="t('rulesets.detail.archive')"
            data-testid="ruleset-archive-confirm"
            @click="setArchived(true)"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
