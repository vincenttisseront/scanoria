<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Mon compte : changement de mot de passe (imposé au premier accès si demandé)
et préférences.
-->

<script setup lang="ts">
import { passwordSchema } from '#shared/schemas'

const { t } = useI18n()
useHead({ title: computed(() => t('account.title')) })

const session = useSession()
const { api, errorMessage } = useApi()
const toast = useToast()

const form = reactive({ current: '', next: '', confirm: '' })
const saving = ref(false)
const mismatch = computed(() => !!form.confirm && form.next !== form.confirm)
const valid = computed(() => !!form.current && passwordSchema.safeParse(form.next).success && form.next === form.confirm)

async function changePassword() {
  saving.value = true
  try {
    await api('/api/auth/password', { method: 'POST', body: { current_password: form.current, new_password: form.next } })
    toast.add({ title: t('account.changed'), color: 'success' })
    const forced = session.state.value.user?.must_change_password
    await session.refresh()
    if (forced) await navigateTo('/')
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    saving.value = false
    Object.assign(form, { current: '', next: '', confirm: '' })
  }
}
</script>

<template>
  <PageShell :title="t('account.title')">
    <UAlert
      v-if="session.state.value.user?.must_change_password"
      color="warning"
      variant="subtle"
      icon="i-lucide-key-round"
      :title="t('account.mustChange')"
    />

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('account.passwordTitle') }}
        </h2>
        <p class="text-sm text-muted">
          {{ session.state.value.user?.username }} · {{ session.state.value.user ? t(`roles.${session.state.value.user.role}`) : '' }}
        </p>
      </template>
      <form
        class="max-w-md space-y-4"
        @submit.prevent="changePassword"
      >
        <UFormField :label="t('account.currentPassword')">
          <UInput
            v-model="form.current"
            type="password"
            autocomplete="current-password"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('account.newPassword')">
          <UInput
            v-model="form.next"
            type="password"
            autocomplete="new-password"
            class="w-full"
          />
        </UFormField>
        <UFormField
          :label="t('account.confirmPassword')"
          :error="mismatch ? t('account.mismatch') : undefined"
        >
          <UInput
            v-model="form.confirm"
            type="password"
            autocomplete="new-password"
            class="w-full"
          />
        </UFormField>
        <UButton
          type="submit"
          :disabled="!valid"
          :loading="saving"
          :label="t('common.save')"
        />
      </form>
    </UCard>

    <UCard>
      <template #header>
        <h2 class="font-semibold">
          {{ t('account.preferences') }}
        </h2>
      </template>
      <div class="flex items-center gap-3 text-sm">
        <span>{{ t('app.language') }}</span>
        <LocaleSwitch />
      </div>
    </UCard>
  </PageShell>
</template>
