<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

<script setup lang="ts">
import type { FormSubmitEvent } from '@nuxt/ui'
import { loginSchema } from '#shared/schemas'

definePageMeta({ layout: 'auth', public: true })

const { t } = useI18n()
useHead({ title: computed(() => t('login.title')) })

const session = useSession()
const { api, errorMessage } = useApi()
const route = useRoute()

const form = reactive({ username: '', password: '' })
const loading = ref(false)
const error = ref('')

const { data: about } = await useFetch<{ version: string, license: string, source_url: string | null }>('/api/about')

async function onSubmit(event: FormSubmitEvent<{ username: string, password: string }>) {
  loading.value = true
  error.value = ''
  try {
    await api('/api/auth/login', { method: 'POST', body: event.data })
    await session.refresh()
    const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') && !route.query.next.startsWith('//')
      ? route.query.next
      : '/'
    await navigateTo(next)
  }
  catch (err) {
    error.value = errorMessage(err)
    form.password = ''
  }
  finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="w-full max-w-sm space-y-4">
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-2 text-lg font-semibold">
        <UIcon
          name="i-lucide-scan-search"
          class="size-7 text-primary"
        />
        {{ t('app.name') }}
      </div>
      <LocaleSwitch />
    </div>
    <UCard>
      <template #header>
        <h1 class="text-xl font-semibold">
          {{ t('login.title') }}
        </h1>
        <p class="text-sm text-muted">
          {{ t('login.subtitle') }}
        </p>
      </template>
      <UForm
        :schema="loginSchema"
        :state="form"
        class="space-y-4"
        @submit="onSubmit"
      >
        <UFormField
          :label="t('login.username')"
          name="username"
        >
          <UInput
            v-model="form.username"
            type="text"
            autocomplete="username"
            autofocus
            class="w-full"
          />
        </UFormField>
        <UFormField
          :label="t('login.password')"
          name="password"
        >
          <UInput
            v-model="form.password"
            type="password"
            autocomplete="current-password"
            class="w-full"
          />
        </UFormField>
        <UAlert
          v-if="error"
          color="error"
          variant="subtle"
          icon="i-lucide-circle-x"
          :title="error"
        />
        <UButton
          type="submit"
          block
          :loading="loading"
          :label="t('login.submit')"
        />
      </UForm>
    </UCard>
    <p class="text-center text-xs text-muted">
      Scanoria {{ about?.version }} · {{ about?.license }} ·
      <a
        v-if="about?.source_url"
        :href="about.source_url"
        class="underline"
        rel="noopener noreferrer"
        target="_blank"
      >{{ t('about.sourceTitle') }}</a>
      <NuxtLink
        v-else
        to="/system/about"
        class="underline"
      >{{ t('nav.about') }}</NuxtLink>
    </p>
  </div>
</template>
