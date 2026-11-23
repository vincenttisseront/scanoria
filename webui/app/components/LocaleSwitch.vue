<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

<script setup lang="ts">
const { locale, locales, setLocale, t } = useI18n()

const items = computed(() =>
  (locales.value as { code: 'fr' | 'en', name?: string }[]).map(l => ({ label: l.name ?? l.code, value: l.code })),
)

const model = computed({
  get: () => locale.value,
  set: (value: string) => {
    void setLocale(value as 'fr' | 'en')
  },
})
</script>

<template>
  <USelect
    v-model="model"
    :items="items"
    :aria-label="t('app.language')"
    icon="i-lucide-languages"
    size="sm"
    class="w-36"
  />
</template>
