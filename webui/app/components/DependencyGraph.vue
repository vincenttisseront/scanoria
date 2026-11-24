<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Graphe des dépendances et conflits entre modules (G1), par module : ce qu'il
requiert (module ou base de vulnérabilités), ce avec quoi il est incompatible.
Avec « focus », seul le voisinage d'un module est montré (requis et requérants).
-->

<script setup lang="ts">
const props = defineProps<{
  edges: { from: string, to: string, kind: 'module' | 'feed' | 'conflict' }[]
  names: Record<string, string>
  installed: string[]
  focus?: string
}>()

const { t } = useI18n()

const visible = computed(() => props.focus
  ? props.edges.filter(e => e.from === props.focus || e.to === props.focus)
  : props.edges)

const rows = computed(() => {
  const byFrom = new Map<string, typeof props.edges>()
  for (const e of visible.value) byFrom.set(e.from, [...(byFrom.get(e.from) ?? []), e])
  return [...byFrom.entries()].sort(([a], [b]) => (props.names[a] ?? a).localeCompare(props.names[b] ?? b))
})

const name = (id: string) => props.names[id] ?? id
const color = (e: { to: string, kind: string }) => {
  if (e.kind === 'conflict') return 'error' as const
  return props.installed.includes(e.to) ? 'success' as const : 'neutral' as const
}
</script>

<template>
  <p
    v-if="!rows.length"
    class="text-sm text-muted"
  >
    {{ t('catalog.graph.empty') }}
  </p>
  <ul
    v-else
    class="space-y-2"
    data-graph
  >
    <li
      v-for="[from, list] in rows"
      :key="from"
      class="flex flex-wrap items-center gap-2 text-sm"
    >
      <NuxtLink
        :to="`/catalog/${from}`"
        class="font-medium hover:underline"
      >
        {{ name(from) }}
      </NuxtLink>
      <UIcon
        name="i-lucide-arrow-right"
        class="size-4 text-muted"
      />
      <UBadge
        v-for="e in list"
        :key="`${e.kind}-${e.to}`"
        :color="color(e)"
        variant="subtle"
        :icon="installed.includes(e.to) && e.kind !== 'conflict' ? 'i-lucide-check' : undefined"
        :label="t(`catalog.graph.${e.kind}`, { name: name(e.to) })"
      />
    </li>
  </ul>
</template>
