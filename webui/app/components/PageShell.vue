<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Cadre commun d'une page : barre de titre et corps défilant.
-->

<script setup lang="ts">
defineProps<{ title: string }>()
</script>

<template>
  <UDashboardPanel>
    <template #header>
      <UDashboardNavbar :title="title">
        <template #leading>
          <UDashboardSidebarCollapse />
        </template>
        <template #right>
          <slot name="actions" />
          <LocaleSwitch />
        </template>
      </UDashboardNavbar>
    </template>
    <template #body>
      <div class="mx-auto w-full max-w-6xl space-y-6">
        <slot />
      </div>
    </template>
  </UDashboardPanel>
</template>
