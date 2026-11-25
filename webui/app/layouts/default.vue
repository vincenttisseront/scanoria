<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront
-->

<script setup lang="ts">
import type { DropdownMenuItem, NavigationMenuItem } from '@nuxt/ui'
import type { CatalogView } from '~/composables/useCatalog'

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

// Applications web des modules « service » installés, sains et actifs
// (section 3.4 : <libellé>.<nom de l'appliance>). Chargées à l'ouverture,
// puis rechargées en quittant le catalogue, ou au changement de page
// quand la dernière lecture date de plus de 30 s.
const route = useRoute()
// Lien affiché seulement en https, vers <libellé>.<nom de l'appliance>.
function safeAppUrl(r: { hostname: string, url: string } | null | undefined): string | null {
  if (!r?.hostname || !r.url) return null
  try {
    const u = new URL(r.url)
    return u.protocol === 'https:' && u.hostname.startsWith(`${r.hostname}.`) && !u.username && !u.password ? u.href : null
  }
  catch {
    return null
  }
}
const serviceApps = ref<{ id: string, name: string, url: string }[]>([])
async function loadServiceApps() {
  try {
    const view = await api<CatalogView>('/api/catalog')
    serviceApps.value = view.modules
      .filter(m => m.installed?.type === 'service' && m.installed.enabled && m.installed.status === 'healthy')
      .flatMap((m) => {
        const url = safeAppUrl(m.installed!.route)
        return url ? [{ id: m.id, name: m.name, url }] : []
      })
      .sort((a, b) => a.name.localeCompare(b.name))
  }
  catch {
    // menu sans les applications : sans conséquence
  }
}
let loadedAt = 0
async function refreshServiceApps() {
  loadedAt = Date.now()
  await loadServiceApps()
}
onMounted(refreshServiceApps)
watch(() => route.path, (to, from) => {
  if (from?.startsWith('/catalog') || Date.now() - loadedAt > 30_000) void refreshServiceApps()
})

// 0.7 (B, F5) : demandes d'exception en attente, pour les administrateurs.
const pending = usePendingExceptions()
onMounted(() => void pending.refresh())
watch(() => route.path, () => void pending.refreshIfStale())

/**
 * Menu latéral en sections : une section = un groupe séparé, titré quand le
 * menu est déplié (le titre disparaît, le séparateur reste, quand il est replié).
 * Ajouter une entrée : la placer dans la section qui correspond à son usage.
 */
const sections = computed<NavigationMenuItem[][]>(() => {
  // Entrée active selon le chemin, sous-pages comprises (/scans/42 → Analyses).
  const under = (p: string) => route.path === p || route.path.startsWith(`${p}/`)
  const systemPages = ['/system/tls', '/system/users', '/system/ai', '/system/audit', '/system/about', '/system/licenses', '/system/offline']
  const section = (label: string, items: (NavigationMenuItem | false)[]): NavigationMenuItem[] =>
    [{ label, type: 'label' }, ...items.filter((i): i is NavigationMenuItem => !!i)]

  return [
    [{ label: t('nav.dashboard'), icon: 'i-lucide-layout-dashboard', to: '/', active: route.path === '/' }],
    section(t('nav.groups.analysis'), [
      { label: t('projects.nav'), icon: 'i-lucide-folder-git-2', to: '/projects', active: under('/projects') },
      { label: t('scans.nav'), icon: 'i-lucide-scan-search', to: '/scans', active: under('/scans') && !under('/scans/health') },
      { label: t('nav.findings'), icon: 'i-lucide-list-checks', to: '/findings', active: under('/findings') && !under('/findings/approvals') },
      session.can('admin') && { label: t('triage.approvals.nav'), icon: 'i-lucide-stamp', to: '/findings/approvals', active: under('/findings/approvals'), badge: pending.count.value ? String(pending.count.value) : undefined },
      { label: t('components.nav'), icon: 'i-lucide-boxes', to: '/components', active: under('/components') },
      { label: t('gates.nav'), icon: 'i-lucide-gauge', to: '/gates', active: under('/gates') },
      { label: t('rulesets.nav'), icon: 'i-lucide-file-code-2', to: '/rulesets', active: under('/rulesets') },
      { label: t('licenses.nav'), icon: 'i-lucide-scale', to: '/system/licenses', active: under('/system/licenses') },
      { label: t('nav.short.health'), icon: 'i-lucide-activity', to: '/scans/health', active: under('/scans/health') },
    ]),
    section(t('nav.groups.modules'), [
      { label: t('nav.catalog'), icon: 'i-lucide-layout-grid', to: '/catalog', active: under('/catalog') || under('/modules') },
      ...serviceApps.value.map(app => ({ label: app.name, icon: 'i-lucide-app-window', to: app.url, target: '_blank' })),
    ]),
    section(t('nav.groups.admin'), [
      { label: t('nav.system'), icon: 'i-lucide-server', to: '/system', active: under('/system') && !systemPages.some(under) },
      { label: t('nav.tls'), icon: 'i-lucide-shield-check', to: '/system/tls', active: under('/system/tls') },
      session.can('admin') && { label: t('nav.users'), icon: 'i-lucide-users', to: '/system/users', active: under('/system/users') },
      session.can('operator') && { label: t('nav.short.ai'), icon: 'i-lucide-sparkles', to: '/system/ai', active: under('/system/ai') },
      session.can('operator') && { label: t('nav.offline'), icon: 'i-lucide-package-open', to: '/system/offline', active: under('/system/offline') },
      session.can('operator') && { label: t('nav.audit'), icon: 'i-lucide-scroll-text', to: '/system/audit', active: under('/system/audit') },
      { label: t('nav.updates'), icon: 'i-lucide-refresh-cw', to: '/updates', active: under('/updates') },
      { label: t('nav.short.about'), icon: 'i-lucide-info', to: '/system/about', active: under('/system/about') },
    ]),
  ]
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
          :items="sections"
          orientation="vertical"
          tooltip
          :aria-label="t('nav.label')"
          :ui="{
            root: 'gap-0',
            label: 'px-2.5 pt-3 pb-1 text-[11px]/4 font-semibold uppercase tracking-wide text-muted',
            link: 'py-1',
            linkLeadingIcon: 'size-4',
            separator: collapsed ? 'my-1.5' : 'hidden',
          }"
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
