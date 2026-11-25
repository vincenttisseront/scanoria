<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Retour de GitHub (J1) : après la création de l'application (?code&state),
puis après son installation (?installation_id&state). Le cookie de session
n'accompagne pas une redirection depuis un autre site (SameSite=Strict) : la
page rappelle donc l'API elle-même, avec la session et le jeton CSRF.
-->

<script setup lang="ts">
const { t } = useI18n()
useHead({ title: computed(() => t('projects.forges.github.title')) })
const route = useRoute()
const { api, message } = useProjects()

const phase = ref<'working' | 'created' | 'installed' | 'error'>('working')
const error = ref('')
const installUrl = ref('')
const slug = ref('')

const STORE = 'scanoria.github-app'
function remember(forgeId: string) {
  try {
    sessionStorage.setItem(STORE, forgeId)
  }
  catch {
    // Stockage indisponible : l'installation sera reprise par son webhook ou par la découverte.
  }
}
function recall(): string | null {
  try {
    return sessionStorage.getItem(STORE)
  }
  catch {
    return null
  }
}

onMounted(async () => {
  const q = route.query
  const str = (v: unknown) => (typeof v === 'string' ? v : '')
  try {
    if (str(q.code) && str(q.state)) {
      const r = await api<{ forge_id: string, slug: string, install_url: string }>('/api/forges/github/convert', {
        method: 'POST', body: { code: str(q.code), state: str(q.state) },
      })
      remember(r.forge_id)
      slug.value = r.slug
      installUrl.value = r.install_url
      phase.value = 'created'
      return
    }
    const forgeId = recall()
    if (str(q.installation_id) && forgeId) {
      await api('/api/forges/github/install', { method: 'POST', body: { forge_id: forgeId, installation_id: str(q.installation_id) } })
      phase.value = 'installed'
      return
    }
    error.value = t('projects.forges.github.missing')
    phase.value = 'error'
  }
  catch (err) {
    error.value = message(err)
    phase.value = 'error'
  }
})
</script>

<template>
  <PageShell :title="t('projects.forges.github.title')">
    <template #actions>
      <UButton
        to="/projects/forges"
        icon="i-lucide-arrow-left"
        color="neutral"
        variant="ghost"
        :label="t('projects.forges.github.back')"
      />
    </template>
    <UCard>
      <div
        v-if="phase === 'working'"
        class="flex items-center gap-2 text-sm text-muted"
        role="status"
      >
        <UIcon
          name="i-lucide-loader-circle"
          class="size-4 animate-spin"
        />
        {{ route.query.code ? t('projects.forges.github.returning') : t('projects.forges.github.installing') }}
      </div>
      <div
        v-else-if="phase === 'created'"
        class="space-y-3"
      >
        <p class="text-sm">
          {{ t('projects.forges.github.created', { slug }) }}
        </p>
        <UButton
          :to="installUrl"
          external
          icon="i-lucide-github"
          :label="t('projects.forges.github.install')"
        />
      </div>
      <UAlert
        v-else-if="phase === 'installed'"
        color="success"
        variant="subtle"
        :title="t('projects.forges.github.installed')"
      />
      <UAlert
        v-else
        color="error"
        variant="subtle"
        :title="error"
      />
    </UCard>
  </PageShell>
</template>
