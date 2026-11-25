<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Inventaire des workflows d'agents d'une analyse (K7, 0.7) : frameworks,
agents, outils, serveurs MCP et arêtes relevés par le module agentic-radar,
sans exécution ni appel de modèle. Les outils qui portent une vulnérabilité
connue sont signalés ; les résultats correspondants sont dans la liste des
résultats. Texte venu du dépôt analysé : affiché comme texte seulement.
Rien n'est affiché si l'analyse n'a pas d'inventaire.
-->

<script setup lang="ts">
interface Node { name: string | null, type: string | null, category: string | null, description: string | null, vulnerabilities: string[] }
interface Workflow {
  framework: string
  name: string | null
  nodes: Node[]
  edges: { start: string | null, end: string | null, condition: string | null }[]
  agents: { name: string | null, llm: string | null, is_guardrail: boolean, system_prompt_chars: number }[]
  tools: Node[]
  mcp_servers: Node[]
}
interface Inventory { module_version: string, frameworks: string[], inventory: { workflows: Workflow[], truncated: boolean } }

const props = defineProps<{ scanId: string }>()
const { t } = useI18n()
const { api } = useApi()
const data = ref<Inventory | null>(null)

onMounted(async () => {
  try {
    data.value = (await api<{ inventory: Inventory | null }>(`/api/scans/${encodeURIComponent(props.scanId)}/agent-inventory`)).inventory
  }
  catch {
    data.value = null
  }
})
</script>

<template>
  <UCard
    v-if="data && data.inventory.workflows.length"
    data-testid="agent-inventory"
  >
    <template #header>
      <h2 class="font-semibold">
        {{ t('scans.agents.title') }}
      </h2>
      <p class="text-sm text-muted">
        {{ t('scans.agents.help', { version: data.module_version }) }}
      </p>
    </template>
    <div class="space-y-4 text-sm">
      <section
        v-for="(w, i) in data.inventory.workflows"
        :key="i"
        class="space-y-2"
      >
        <h3 class="flex flex-wrap items-center gap-2 font-semibold">
          <UBadge
            color="neutral"
            variant="subtle"
            :label="w.framework"
          />
          {{ w.name ?? '—' }}
        </h3>
        <p
          v-if="w.agents.length"
          class="text-muted"
        >
          {{ t('scans.agents.agents') }} :
          <span
            v-for="(a, j) in w.agents"
            :key="j"
          >{{ j ? ', ' : '' }}{{ a.name }}<template v-if="a.llm"> ({{ a.llm }})</template><template v-if="a.is_guardrail"> · {{ t('scans.agents.guardrail') }}</template></span>
        </p>
        <ul class="space-y-1">
          <li
            v-for="(tool, j) in [...w.tools, ...w.mcp_servers]"
            :key="j"
            class="flex flex-wrap items-center gap-2"
          >
            <UIcon :name="tool.type === 'mcp_server' ? 'i-lucide-server' : 'i-lucide-wrench'" />
            <span>{{ tool.name }}</span>
            <span
              v-if="tool.category"
              class="text-muted"
            >{{ tool.category }}</span>
            <UBadge
              v-for="v in tool.vulnerabilities"
              :key="v"
              color="warning"
              variant="subtle"
              :label="v"
            />
          </li>
        </ul>
        <p class="text-xs text-muted">
          {{ t('scans.agents.graph', { nodes: w.nodes.length, edges: w.edges.length }) }}
        </p>
      </section>
      <p
        v-if="data.inventory.truncated"
        class="text-xs text-muted"
      >
        {{ t('scans.agents.truncated') }}
      </p>
    </div>
  </UCard>
</template>
