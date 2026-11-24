<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Résultat de l'assistant F1 : ce qui a été trouvé dans le dépôt et pourquoi la
console en déduit catégories, profil et modules. Les modules pertinents non
installés ont un bouton qui ouvre le plan d'installation : rien n'est
installé sans confirmation.
-->

<script setup lang="ts">
import type { ProjectDetection } from '~/composables/useProjects'

const props = defineProps<{ detection: ProjectDetection | null, canInstall?: boolean }>()
const { t } = useI18n()
const fmt = useFormat()
const { label } = useProjects()

const d = computed(() => props.detection)
const iacList = computed(() => {
  const iac = d.value?.iac
  if (!iac) return []
  return (['terraform', 'kubernetes', 'helm', 'ansible'] as const).filter(k => iac[k])
})
const languageText = computed(() => {
  const det = d.value
  return det?.languages?.length ? det.languages.map(l => `${l} (${det.language_files?.[l] ?? 0})`).join(', ') : ''
})
const missing = computed(() => d.value?.modules?.filter(m => !m.installed) ?? [])
const installed = computed(() => d.value?.modules?.filter(m => m.installed) ?? [])

const installOpen = ref(false)
const installRequest = ref<{ modules: { id: string }[] } | null>(null)
function install(ids: string[]) {
  installRequest.value = { modules: ids.map(id => ({ id })) }
  installOpen.value = true
}
</script>

<template>
  <div class="space-y-4">
    <UAlert
      v-if="!d"
      color="neutral"
      variant="subtle"
      icon="i-lucide-loader-circle"
      :title="t('projects.detection.pending')"
    />
    <UAlert
      v-else-if="d.error"
      color="warning"
      variant="subtle"
      icon="i-lucide-triangle-alert"
      :title="label('errors', d.error)"
      :description="t('projects.detection.errorHelp')"
    />
    <template v-else>
      <p class="text-xs text-muted">
        {{ t('projects.detection.analyzed', { date: fmt.date(d.analyzed_at), ref: d.ref ?? '—', files: d.files ?? 0 }) }}
        <span v-if="d.truncated"> · {{ t('projects.detection.truncated') }}</span>
      </p>
      <dl class="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[12rem_1fr]">
        <dt class="text-muted">
          {{ t('projects.languages') }}
        </dt>
        <dd>{{ languageText || t('common.none') }}</dd>
        <dt class="text-muted">
          {{ t('projects.detection.packages') }}
        </dt>
        <dd>
          <span v-if="!d.package_managers?.length">{{ t('common.none') }}</span>
          <ul v-else>
            <li
              v-for="pm in d.package_managers"
              :key="pm.manifest"
              class="font-mono text-xs"
            >
              {{ pm.name }} · {{ pm.manifest }} →
              <span v-if="pm.lockfile">{{ pm.lockfile }}</span>
              <span
                v-else
                class="text-warning"
              >{{ t('projects.detection.noLockfile') }}</span>
            </li>
          </ul>
        </dd>
        <dt class="text-muted">
          {{ t('projects.detection.containers') }}
        </dt>
        <dd class="font-mono text-xs">
          {{ d.containers?.length ? d.containers.join(', ') : t('common.none') }}
        </dd>
        <dt class="text-muted">
          {{ t('projects.detection.iac') }}
        </dt>
        <dd>{{ iacList.length ? iacList.join(', ') : t('common.none') }}</dd>
        <dt class="text-muted">
          {{ t('projects.detection.ci') }}
        </dt>
        <dd class="font-mono text-xs">
          {{ d.ci?.length ? d.ci.map(c => c.path).join(', ') : t('common.none') }}
        </dd>
        <dt class="text-muted">
          {{ t('projects.detection.license') }}
        </dt>
        <dd>{{ d.license ? `${d.license.spdx} (${d.license.source})` : t('projects.detection.noLicense') }}</dd>
        <dt class="text-muted">
          {{ t('projects.detection.categories') }}
        </dt>
        <dd class="flex flex-wrap gap-1">
          <UBadge
            v-for="c in d.categories ?? []"
            :key="c"
            color="neutral"
            variant="subtle"
            :label="label('category', c)"
          />
        </dd>
        <dt class="text-muted">
          {{ t('projects.detection.profile') }}
        </dt>
        <dd>{{ t('projects.detection.profileWhy', { profile: d.profile ?? 'complet', pr: d.pr_profile ?? 'rapide' }) }}</dd>
      </dl>

      <UAlert
        v-if="d.missing_lockfiles?.length"
        color="warning"
        variant="subtle"
        icon="i-lucide-lock-open"
        :title="t('projects.detection.missingLockfiles')"
        :description="d.missing_lockfiles.join(', ')"
      />
      <UAlert
        v-if="d.coverage_gaps?.length"
        color="warning"
        variant="subtle"
        icon="i-lucide-shield-off"
        :title="t('projects.detection.gaps')"
        :description="d.coverage_gaps.map(c => label('category', c)).join(', ')"
      />

      <div class="space-y-2">
        <h3 class="text-sm font-semibold">
          {{ t('projects.detection.modules') }}
        </h3>
        <ul class="space-y-1 text-sm">
          <li
            v-for="m in installed"
            :key="m.id"
            class="flex items-center gap-2"
          >
            <UIcon
              :name="m.enabled ? 'i-lucide-check' : 'i-lucide-pause'"
              class="size-4"
              :class="m.enabled ? 'text-success' : 'text-warning'"
            />
            <span class="font-medium">{{ m.name }}</span>
            <span class="text-muted">{{ label('reason', m.reason) }}</span>
          </li>
          <li
            v-for="m in missing"
            :key="m.id"
            class="flex flex-wrap items-center gap-2"
          >
            <UIcon
              name="i-lucide-package-plus"
              class="size-4 text-muted"
            />
            <span class="font-medium">{{ m.name }}</span>
            <span class="text-muted">{{ label('reason', m.reason) }} · {{ t('projects.detection.notInstalled') }}</span>
            <UButton
              v-if="canInstall"
              size="xs"
              color="neutral"
              variant="subtle"
              :label="t('projects.detection.install')"
              @click="install([m.id])"
            />
          </li>
        </ul>
        <UButton
          v-if="canInstall && missing.length > 1"
          size="sm"
          icon="i-lucide-package-plus"
          :label="t('projects.detection.installAll', { n: missing.length })"
          @click="install(missing.map(m => m.id))"
        />
      </div>
    </template>

    <InstallPlanModal
      v-model:open="installOpen"
      :title="t('projects.detection.installTitle')"
      :request="installRequest"
    />
  </div>
</template>
