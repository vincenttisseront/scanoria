<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

<script setup lang="ts">
import type { DropdownMenuItem, NavigationMenuItem } from '@nuxt/ui'

const { t, locale, setLocale } = useI18n()
const session = useSession()
const { api, errorMessage } = useApi()
const toast = useToast()
const loggingOut = ref(false)

const user = computed(() => session.state.value.user)

// Langue : celle du compte au chargement, puis enregistrée à chaque changement.
const appliedUserLocale = ref(false)
watchEffect(() => {
  if (user.value && !appliedUserLocale.value) {
    appliedUserLocale.value = true
    if (user.value.locale !== locale.value) void setLocale(user.value.locale)
  }
})
watch(locale, async (value) => {
  const u = user.value
  if (!u || u.locale === value || (value !== 'fr' && value !== 'en')) return
  try {
    await api('/api/account', { method: 'PATCH', body: { locale: value } })
    u.locale = value
  }
  catch {
    // préférence non enregistrée : sans conséquence
  }
})

const links = computed<NavigationMenuItem[]>(() => {
  const items: NavigationMenuItem[] = [
    { label: t('nav.dashboard'), icon: 'i-lucide-layout-dashboard', to: '/' },
    { label: t('projects.nav'), icon: 'i-lucide-folder-git-2', to: '/projects' },
    { label: t('scans.nav'), icon: 'i-lucide-scan-search', to: '/scans' },
    { label: t('nav.findings'), icon: 'i-lucide-list-checks', to: '/findings' },
    { label: t('nav.catalog'), icon: 'i-lucide-layout-grid', to: '/catalog' },
    { label: t('nav.updates'), icon: 'i-lucide-refresh-cw', to: '/updates' },
    { label: t('nav.system'), icon: 'i-lucide-server', to: '/system' },
    { label: t('nav.tls'), icon: 'i-lucide-shield-check', to: '/system/tls' },
  ]
  if (session.can('admin')) items.push({ label: t('nav.users'), icon: 'i-lucide-users', to: '/system/users' })
  if (session.can('operator')) items.push({ label: t('nav.audit'), icon: 'i-lucide-scroll-text', to: '/system/audit' })
  items.push({ label: t('nav.about'), icon: 'i-lucide-info', to: '/system/about' })
  return items
})

async function logout() {
  loggingOut.value = true
  try {
    await api('/api/auth/logout', { method: 'POST' })
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loggingOut.value = false
    session.clear()
    await navigateTo('/login')
  }
}

const userMenu = computed<DropdownMenuItem[][]>(() => [
  [{ label: t('nav.account'), icon: 'i-lucide-user-cog', to: '/account' }],
  [{ label: t('nav.logout'), icon: 'i-lucide-log-out', onSelect: () => void logout() }],
])
</script>

<template>
  <UDashboardGroup>
    <UDashboardSidebar
      collapsible
      :ui="{ footer: 'border-t border-default' }"
    >
      <template #header="{ collapsed }">
        <NuxtLink
          to="/"
          class="flex items-center gap-2 font-semibold"
        >
          <UIcon
            name="i-lucide-scan-search"
            class="size-6 text-primary"
          />
          <span v-if="!collapsed">{{ t('app.name') }}</span>
        </NuxtLink>
      </template>

      <template #default="{ collapsed }">
        <UNavigationMenu
          :collapsed="collapsed"
          :items="links"
          orientation="vertical"
        />
      </template>

      <template #footer="{ collapsed }">
        <UDropdownMenu
          v-if="user"
          :items="userMenu"
          :content="{ align: 'start' }"
        >
          <UButton
            color="neutral"
            variant="ghost"
            block
            :loading="loggingOut"
            :label="collapsed ? undefined : user.display_name || user.username"
            :trailing-icon="collapsed ? undefined : 'i-lucide-chevrons-up-down'"
            icon="i-lucide-circle-user"
          />
        </UDropdownMenu>
      </template>
    </UDashboardSidebar>

    <slot />
  </UDashboardGroup>
</template>
