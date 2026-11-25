<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Aperçu d'un profil avant enregistrement (G10) : modules résolus sur les
modules installés, modules manquants avec un lien vers le catalogue, durée et
ressources estimées (durées mesurées, F14), couverture obtenue sur un dépôt
choisi (détection F1) et verrous qui seraient refusés. Lecture seule.
-->

<script setup lang="ts">
const props = defineProps<{ draft: Record<string, unknown> }>()
const { t, te } = useI18n()
const { api, errorMessage } = useApi()

const projects = ref<{ label: string, value: string }[]>([])
const NONE = '__none__'
const projectId = ref(NONE)
const preview = ref<ProfilePreview | null>(null)
const loading = ref(false)
const error = ref('')

onMounted(async () => {
  try {
    const res = await api<{ items: { id: string, name: string, slug: string, source_kind: string }[] }>('/api/projects')
    projects.value = res.items.filter(p => p.source_kind === 'git').map(p => ({ label: `${p.name} (${p.slug})`, value: p.id }))
  }
  catch {
    projects.value = []
  }
})
const projectItems = computed(() => [{ label: t('profiles.preview.noProject'), value: NONE }, ...projects.value])

async function run() {
  loading.value = true
  error.value = ''
  try {
    preview.value = await api<ProfilePreview>('/api/profiles/preview', {
      method: 'POST',
      body: { ...props.draft, ...(projectId.value !== NONE ? { project_id: projectId.value } : {}) },
    })
  }
  catch (err) {
    error.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
}
watch(projectId, () => {
  if (preview.value) void run()
})

const cat = (c: string) => (te(`findings.categories.${c}`) ? t(`findings.categories.${c}`) : c)
const duration = (ms: number) => (ms >= 60_000 ? t('profiles.preview.minutes', { n: Math.round(ms / 6000) / 10 }) : t('profiles.preview.seconds', { n: Math.max(1, Math.round(ms / 1000)) }))
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-wrap items-end gap-3">
      <UFormField
        :label="t('profiles.preview.project')"
        :help="t('profiles.preview.projectHelp')"
        class="min-w-64 flex-1"
      >
        <USelect
          v-model="projectId"
          :items="projectItems"
          class="w-full"
        />
      </UFormField>
      <UButton
        icon="i-lucide-eye"
        color="neutral"
        variant="subtle"
        :loading="loading"
        :label="t('profiles.preview.run')"
        data-testid="profile-preview"
        @click="run"
      />
    </div>

    <div
      v-if="loading && !preview"
      class="flex items-center gap-2 text-sm text-muted"
      role="status"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('profiles.preview.loading') }}
    </div>
    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      :title="error"
    />

    <div
      v-if="preview"
      class="space-y-4"
      :class="{ 'opacity-60': loading }"
      data-testid="profile-preview-result"
    >
      <UAlert
        v-if="preview.violations.length"
        color="error"
        variant="subtle"
        icon="i-lucide-lock"
        :title="t('profiles.errors.E_PROFILE_LOCKED')"
      >
        <template #description>
          <ul class="list-disc ps-5">
            <li
              v-for="v in preview.violations"
              :key="v.field"
            >
              {{ t('profiles.violation', { field: lockFieldLabel(v.field, t, te), locked: lockValueLabel(v.locked, t, te), requested: lockValueLabel(v.requested, t, te) }) }}
            </li>
          </ul>
        </template>
      </UAlert>

      <p class="text-sm">
        {{ t('profiles.preview.chain') }} <span class="font-mono">{{ preview.effective.chain.join(' › ') }}</span>
      </p>

      <div class="grid gap-3 sm:grid-cols-3">
        <UCard>
          <p class="text-xs text-muted">
            {{ t('profiles.preview.duration') }}
          </p>
          <p class="text-lg font-semibold">
            {{ preview.estimate.duration_ms ? duration(preview.estimate.duration_ms) : '—' }}
          </p>
          <p
            v-if="preview.estimate.unmeasured.length"
            class="text-xs text-muted"
          >
            {{ t('profiles.preview.unmeasured', { list: preview.estimate.unmeasured.join(', ') }) }}
          </p>
        </UCard>
        <UCard>
          <p class="text-xs text-muted">
            {{ t('profiles.preview.ram') }}
          </p>
          <p class="text-lg font-semibold">
            {{ preview.estimate.peak_ram_mb ? t('profiles.preview.mb', { n: preview.estimate.peak_ram_mb }) : '—' }}
          </p>
        </UCard>
        <UCard>
          <p class="text-xs text-muted">
            {{ t('profiles.preview.cpu') }}
          </p>
          <p class="text-lg font-semibold">
            {{ preview.estimate.peak_cpu || '—' }}
          </p>
        </UCard>
      </div>

      <div>
        <h3 class="text-sm font-medium">
          {{ t('profiles.preview.modules', { n: preview.modules.length }) }}
        </h3>
        <p
          v-if="!preview.modules.length"
          class="text-sm text-muted"
        >
          {{ t('profiles.preview.noModules') }}
        </p>
        <ul class="mt-1 space-y-1 text-sm">
          <li
            v-for="m in preview.modules"
            :key="m.id"
            class="flex flex-wrap items-center gap-2"
          >
            <span class="font-mono">{{ m.id }}</span>
            <span class="text-muted">{{ m.version }}</span>
            <UBadge
              v-for="c in m.categories"
              :key="c"
              color="neutral"
              variant="outline"
              size="sm"
              :label="cat(c)"
            />
            <span
              v-if="m.expected_ms !== null"
              class="text-xs text-muted"
            >{{ duration(m.expected_ms) }} · {{ t(`profiles.preview.measured.${m.measured}`) }}</span>
          </li>
        </ul>
      </div>

      <div v-if="preview.missing.length">
        <h3 class="text-sm font-medium">
          {{ t('profiles.preview.missing') }}
        </h3>
        <ul class="mt-1 space-y-1 text-sm">
          <li
            v-for="(g, i) in preview.missing"
            :key="i"
            class="flex flex-wrap items-center gap-2"
          >
            <UIcon
              name="i-lucide-circle-alert"
              class="size-4 text-warning"
            />
            <span>{{ g.category ? cat(g.category) : g.module }}</span>
            <template v-if="g.install.length">
              <span class="text-muted">{{ t('profiles.preview.install') }}</span>
              <ULink
                v-for="m in g.install"
                :key="m.id"
                :to="`/catalog/${m.id}`"
                class="font-mono"
              >
                {{ m.name }}
              </ULink>
            </template>
            <span
              v-else
              class="text-muted"
            >{{ t('profiles.preview.noCandidate') }}</span>
          </li>
        </ul>
      </div>

      <div v-if="preview.coverage">
        <h3 class="text-sm font-medium">
          {{ t('profiles.preview.coverage') }}
        </h3>
        <p
          v-if="!preview.coverage.detected"
          class="text-sm text-muted"
        >
          {{ t('profiles.preview.notDetected') }}
        </p>
        <dl
          v-else
          class="mt-1 grid gap-x-4 gap-y-1 text-sm sm:grid-cols-[10rem_1fr]"
        >
          <dt class="text-muted">
            {{ t('profiles.preview.covered') }}
          </dt>
          <dd>{{ preview.coverage.covered.map(cat).join(', ') || '—' }}</dd>
          <dt class="text-muted">
            {{ t('profiles.preview.uncovered') }}
          </dt>
          <dd :class="{ 'text-warning': preview.coverage.uncovered.length }">
            {{ preview.coverage.uncovered.map(cat).join(', ') || '—' }}
          </dd>
          <dt class="text-muted">
            {{ t('profiles.preview.unused') }}
          </dt>
          <dd>{{ preview.coverage.unused.map(cat).join(', ') || '—' }}</dd>
        </dl>
      </div>
    </div>
  </div>
</template>
