<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

<script setup lang="ts">
import { en, fr } from '@nuxt/ui/locale'

const { locale } = useI18n()
const uiLocale = computed(() => (locale.value === 'en' ? en : fr))

useHead({
  htmlAttrs: { lang: computed(() => locale.value) },
  titleTemplate: title => (title ? `${title} · Scanoria` : 'Scanoria'),
})
</script>

<template>
  <UApp :locale="uiLocale">
    <NuxtLayout>
      <NuxtPage />
    </NuxtLayout>
  </UApp>
</template>
