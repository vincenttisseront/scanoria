<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

À propos et licence : AGPL-3.0-or-later, lien vers le code source de la
version installée (article 13). Page publique.
-->

<script setup lang="ts">
definePageMeta({ public: true })

const { t } = useI18n()
useHead({ title: computed(() => t('about.title')) })

interface About {
  product: string
  version: string
  license: string
  copyright: string
  license_url: string
  source_url: string | null
  repository_url: string | null
}
const { data: about, status } = await useFetch<About>('/api/about')
</script>

<template>
  <PageShell :title="t('about.title')">
    <div
      v-if="status === 'pending'"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>
    <UCard v-if="about">
      <dl class="grid gap-2 text-sm md:grid-cols-[max-content_1fr] md:gap-x-6">
        <dt class="text-muted">
          {{ t('about.product') }}
        </dt>
        <dd>{{ about.product }}</dd>
        <dt class="text-muted">
          {{ t('about.version') }}
        </dt>
        <dd>{{ about.version }}</dd>
        <dt class="text-muted">
          {{ t('about.license') }}
        </dt>
        <dd>
          {{ about.license }} ·
          <a
            :href="about.license_url"
            class="text-primary underline"
            target="_blank"
            rel="noopener noreferrer"
          >{{ t('about.licenseLink') }}</a>
        </dd>
      </dl>
      <p class="mt-4 text-sm">
        {{ about.copyright }}
      </p>
      <p class="mt-2 text-sm text-muted">
        {{ t('about.licenseText') }}
      </p>
    </UCard>

    <UCard v-if="about">
      <template #header>
        <h2 class="font-semibold">
          {{ t('about.sourceTitle') }}
        </h2>
      </template>
      <p class="text-sm">
        {{ t('about.sourceText') }}
      </p>
      <p class="mt-2">
        <UButton
          v-if="about.source_url"
          :to="about.source_url"
          external
          target="_blank"
          rel="noopener noreferrer"
          icon="i-lucide-code"
          variant="link"
          class="px-0"
          :label="t('about.sourceLink', { version: about.version })"
        />
        <span
          v-else
          class="text-sm text-warning"
        >{{ t('about.sourceUnavailable') }}</span>
      </p>
      <p class="mt-4 text-xs text-muted">
        {{ t('about.modulesNote') }}
      </p>
    </UCard>
  </PageShell>
</template>
