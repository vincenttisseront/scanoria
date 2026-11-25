<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Détail d'un profil (G8, G10) : catégories et modules, verrous (administrateur)
à côté des verrous hérités, aperçu avant enregistrement, projets qui
l'utilisent par déclencheur, archivage confirmé dans une modale.
-->

<script setup lang="ts">
import { CATEGORIES, type Category, type ProfileLocks } from '#shared/analysis'

const { t, te } = useI18n()
const route = useRoute()
const { api, errorMessage } = useApi()
const toast = useToast()
const fmt = useFormat()
const session = useSession()

interface Detail {
  profile: ProfileRow
  inherited_locks: ProfileLocks
  effective: { chain: { id: string, slug: string, level: ProfileLevel }[], categories: string[], include_modules: string[], exclude_modules: string[], locks: ProfileLocks }
  projects: { id: string, slug: string, name: string, slots: ProfileSlot[] }[]
}

const id = computed(() => String(route.params.id))
const detail = ref<Detail | null>(null)
const loadError = ref('')
const profile = computed(() => detail.value?.profile ?? null)
const canEdit = computed(() => session.can('admin') && !!profile.value && !profile.value.archived_at)
useHead({ title: computed(() => profile.value ? `${t('profiles.title')} · ${profile.value.slug}` : t('profiles.title')) })

const form = reactive({ description: '', categories: [] as Category[], include_modules: [] as string[], exclude_modules: [] as string[], locks: emptyLocks() })
function fill(p: ProfileRow) {
  Object.assign(form, {
    description: p.description ?? '', categories: [...p.categories] as Category[], include_modules: [...p.include_modules], exclude_modules: [...p.exclude_modules], locks: cloneLocks(p.locks),
  })
}
async function load() {
  try {
    detail.value = await api<Detail>(`/api/profiles/${id.value}`)
    fill(detail.value.profile)
    loadError.value = ''
  }
  catch (err) {
    loadError.value = message(err)
  }
}
onMounted(load)

const violations = ref<LockViolation[]>([])
const violationProfile = ref('')
function message(err: unknown): string {
  const { code } = profileErrorDetails(err)
  return code && te(`profiles.errors.${code}`) ? t(`profiles.errors.${code}`) : errorMessage(err)
}

const categoryItems = computed(() => CATEGORIES.map(c => ({ label: te(`findings.categories.${c}`) ? t(`findings.categories.${c}`) : c, value: c })))
const modules = (v: string[]) => v.map(x => x.trim().toLowerCase()).filter(Boolean)

const body = computed(() => ({
  description: form.description.trim() || null,
  categories: form.categories,
  include_modules: form.include_modules,
  exclude_modules: form.exclude_modules,
  locks: form.locks,
}))
const dirty = computed(() => {
  const p = profile.value
  if (!p) return false
  return JSON.stringify(body.value) !== JSON.stringify({
    description: p.description, categories: p.categories, include_modules: p.include_modules, exclude_modules: p.exclude_modules, locks: cloneLocks(p.locks),
  })
})
/** Brouillon pour l'aperçu : le profil tel qu'il serait enregistré. */
const draft = computed(() => ({
  profile_id: id.value, parent_id: profile.value?.parent_id ?? null, slug: profile.value?.slug ?? 'apercu',
  categories: form.categories, include_modules: form.include_modules, exclude_modules: form.exclude_modules, locks: form.locks,
}))

const saving = ref(false)
async function save() {
  saving.value = true
  violations.value = []
  try {
    await api(`/api/profiles/${id.value}`, { method: 'PATCH', body: body.value })
    toast.add({ title: t('profiles.saved'), color: 'success' })
    await load()
  }
  catch (err) {
    const d = profileErrorDetails(err)
    violations.value = d.violations
    violationProfile.value = d.profile && d.profile !== profile.value?.slug ? d.profile : ''
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    saving.value = false
  }
}

const archiveOpen = ref(false)
const archiving = ref(false)
async function setArchived(archived: boolean) {
  archiving.value = true
  try {
    await api(`/api/profiles/${id.value}/archive`, { method: 'POST', body: { archived } })
    archiveOpen.value = false
    toast.add({ title: archived ? t('profiles.archivedDone') : t('profiles.restored'), color: 'success' })
    await load()
  }
  catch (err) {
    toast.add({ title: message(err), color: 'error' })
  }
  finally {
    archiving.value = false
  }
}
</script>

<template>
  <PageShell :title="profile ? profile.slug : t('profiles.title')">
    <template #actions>
      <UButton
        to="/profiles"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('profiles.title')"
      />
    </template>

    <UAlert
      v-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <div
      v-else-if="!profile"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="profile && detail">
      <UAlert
        v-if="profile.archived_at"
        color="warning"
        variant="subtle"
        icon="i-lucide-archive"
        :title="t('profiles.archivedOn', { date: fmt.date(profile.archived_at) })"
      />

      <UCard>
        <dl class="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_1fr]">
          <dt class="text-muted">
            {{ t('profiles.level') }}
          </dt>
          <dd>
            {{ t(`profiles.levels.${profile.level}`) }}
            <UBadge
              v-if="profile.builtin"
              class="ms-2"
              color="neutral"
              variant="subtle"
              size="sm"
              :label="t('profiles.builtin')"
            />
          </dd>
          <dt class="text-muted">
            {{ t('profiles.chain') }}
          </dt>
          <dd class="flex flex-wrap items-center gap-1">
            <template
              v-for="(c, i) in detail.effective.chain"
              :key="c.id"
            >
              <UIcon
                v-if="i"
                name="i-lucide-chevron-right"
                class="size-4 text-muted"
              />
              <ULink
                v-if="c.id !== profile.id"
                :to="`/profiles/${c.id}`"
              >
                {{ c.slug }}
              </ULink>
              <span
                v-else
                class="font-medium"
              >{{ c.slug }}</span>
            </template>
          </dd>
          <dt class="text-muted">
            {{ t('profiles.effectiveCategories') }}
          </dt>
          <dd>{{ detail.effective.categories.map(c => te(`findings.categories.${c}`) ? t(`findings.categories.${c}`) : c).join(', ') || '—' }}</dd>
          <dt class="text-muted">
            {{ t('profiles.rulesets') }}
          </dt>
          <dd data-testid="profile-rulesets">
            <template v-if="profile.rulesets.length">
              <span
                v-for="(r, i) in profile.rulesets"
                :key="r.ruleset_id"
              >{{ i ? ', ' : '' }}<span class="font-mono">{{ r.slug }}</span> ({{ r.engine }}{{ r.pinned_version !== null ? ` v${r.pinned_version}` : '' }})</span>
            </template>
            <template v-else>
              —
            </template>
          </dd>
        </dl>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('profiles.content') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('profiles.contentHelp') }}
          </p>
        </template>
        <div class="grid gap-4 sm:grid-cols-2">
          <UFormField
            :label="t('profiles.description')"
            class="sm:col-span-2"
          >
            <UTextarea
              v-model="form.description"
              class="w-full"
              :rows="2"
              :disabled="!canEdit"
            />
          </UFormField>
          <UFormField
            :label="t('profiles.categories')"
            :help="t('profiles.categoriesHelp')"
            class="sm:col-span-2"
          >
            <USelectMenu
              v-model="form.categories"
              :items="categoryItems"
              value-key="value"
              multiple
              class="w-full"
              :disabled="!canEdit"
              data-testid="profile-categories"
            />
          </UFormField>
          <UFormField
            :label="t('profiles.include')"
            :help="t('profiles.includeHelp')"
          >
            <UInputTags
              :model-value="form.include_modules"
              class="w-full"
              :disabled="!canEdit"
              @update:model-value="(v: string[]) => form.include_modules = modules(v)"
            />
          </UFormField>
          <UFormField
            :label="t('profiles.exclude')"
            :help="t('profiles.excludeHelp')"
          >
            <UInputTags
              :model-value="form.exclude_modules"
              class="w-full"
              :disabled="!canEdit"
              @update:model-value="(v: string[]) => form.exclude_modules = modules(v)"
            />
          </UFormField>
        </div>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('profiles.locks.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('profiles.locks.help') }}
          </p>
        </template>
        <ProfilesLocksEditor
          v-model="form.locks"
          :inherited="detail.inherited_locks"
          :disabled="!canEdit"
        />
      </UCard>

      <UAlert
        v-if="violations.length"
        color="error"
        variant="subtle"
        icon="i-lucide-lock"
        :title="violationProfile ? t('profiles.violationChild', { profile: violationProfile }) : t('profiles.errors.E_PROFILE_LOCKED')"
        data-testid="profile-violations"
      >
        <template #description>
          <ul class="list-disc ps-5">
            <li
              v-for="v in violations"
              :key="v.field"
            >
              {{ t('profiles.violation', { field: lockFieldLabel(v.field, t, te), locked: lockValueLabel(v.locked, t, te), requested: lockValueLabel(v.requested, t, te) }) }}
            </li>
          </ul>
        </template>
      </UAlert>

      <div
        v-if="canEdit"
        class="flex justify-end"
      >
        <UButton
          :loading="saving"
          :disabled="!dirty"
          :label="t('common.save')"
          data-testid="profile-save"
          @click="save"
        />
      </div>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('profiles.preview.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('profiles.preview.help') }}
          </p>
        </template>
        <ProfilesProfilePreview
          v-if="session.can('operator')"
          :draft="draft"
        />
        <p
          v-else
          class="text-sm text-muted"
        >
          {{ t('profiles.preview.operatorOnly') }}
        </p>
      </UCard>

      <UCard>
        <template #header>
          <h2 class="font-semibold">
            {{ t('profiles.usedBy', { n: detail.projects.length }) }}
          </h2>
        </template>
        <p
          v-if="!detail.projects.length"
          class="text-sm text-muted"
        >
          {{ t('profiles.unused') }}
        </p>
        <ul class="space-y-1 text-sm">
          <li
            v-for="p in detail.projects"
            :key="p.id"
            class="flex flex-wrap items-center gap-2"
          >
            <ULink :to="`/projects/${p.id}`">
              {{ p.name }}
            </ULink>
            <UBadge
              v-for="s in p.slots"
              :key="s"
              color="neutral"
              variant="outline"
              size="sm"
              :label="t(`profiles.slots.${s}`)"
            />
          </li>
        </ul>
      </UCard>

      <UCard v-if="session.can('admin') && !profile.builtin">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <p class="text-sm text-muted">
            {{ profile.archived_at ? t('profiles.restoreHelp') : t('profiles.archiveHelp') }}
          </p>
          <UButton
            :icon="profile.archived_at ? 'i-lucide-archive-restore' : 'i-lucide-archive'"
            color="neutral"
            variant="subtle"
            :loading="archiving"
            :disabled="!profile.archived_at && (profile.projects > 0 || profile.children > 0)"
            :label="profile.archived_at ? t('profiles.restore') : t('profiles.archive')"
            data-testid="profile-archive"
            @click="profile.archived_at ? setArchived(false) : archiveOpen = true"
          />
        </div>
      </UCard>

      <ConfirmModal
        v-model:open="archiveOpen"
        :title="t('profiles.archiveTitle', { slug: profile.slug })"
        :body="t('profiles.archiveBody')"
        :confirm-label="t('profiles.archive')"
        :loading="archiving"
        @confirm="setArchived(true)"
      />
    </template>
  </PageShell>
</template>
