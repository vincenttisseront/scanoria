<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Page publique servie à la place d'une application de module absente ou
désactivée (§ 3.4) : nginx redirige <libellé>.<nom> ici, jamais vers
l'application. Aucun appel à l'API : rien n'est révélé sans session.
-->

<script setup lang="ts">
import { MODULE_ID_RE } from '#shared/schemas'

definePageMeta({ layout: 'auth', public: true })

const { t } = useI18n()
const route = useRoute()
useHead({ title: computed(() => t('catalog.unavailable.title')) })

const moduleId = computed(() => {
  const m = route.query.m
  return typeof m === 'string' && MODULE_ID_RE.test(m) ? m : null
})
</script>

<template>
  <UCard class="w-full max-w-md">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon
          name="i-lucide-plug-zap"
          class="size-6 text-warning"
        />
        <h1 class="text-lg font-semibold">
          {{ t('catalog.unavailable.title') }}
        </h1>
      </div>
    </template>
    <p class="text-sm">
      {{ moduleId ? t('catalog.unavailable.body', { module: moduleId }) : t('catalog.unavailable.bodyUnknown') }}
    </p>
    <p class="mt-2 text-sm text-muted">
      {{ t('catalog.unavailable.help') }}
    </p>
    <template #footer>
      <div class="flex items-center justify-between gap-2">
        <UButton
          :to="moduleId ? `/catalog/${moduleId}` : '/catalog'"
          icon="i-lucide-layout-grid"
          :label="t('catalog.unavailable.open')"
        />
        <LocaleSwitch />
      </div>
    </template>
  </UCard>
</template>
