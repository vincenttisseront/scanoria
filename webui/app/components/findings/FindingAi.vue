<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Sorties IA d'un résultat dans le panneau de détail : pré-tri suggéré à côté
du statut « nouveau » (I3), explication (I2) et traduction de la règle
(I17) ; 0.5 : résultats semblables (I7) et atteignabilité d'une
vulnérabilité de dépendance (I11) ; 0.7 : générateur de règles (I12),
enregistrement confirmé par un administrateur seulement. Sans connecteur IA, rien n'est affiché et rien d'autre ne change
(CLAUDE.md § 3.5). Aucune de ces sorties ne modifie le statut du résultat.
-->

<script setup lang="ts">
defineProps<{
  findingId: string
  projectId: string
  status?: string
  title?: string
  secret?: boolean
}>()
// I7 : un tri commun fait depuis les semblables rafraîchit la page ; un semblable s'ouvre dans le panneau.
const emit = defineEmits<{ triaged: [], open: [id: string] }>()
</script>

<template>
  <div
    data-slot="finding-ai"
    class="space-y-3"
  >
    <AiTriage
      v-if="status === 'new'"
      :finding-id="findingId"
    />
    <AiExplanation
      kind="explain-finding"
      :subject-id="findingId"
    />
    <AiRuleTranslation
      v-if="!secret && title"
      :finding-id="findingId"
      :original="title"
    />
    <AiReachability :finding-id="findingId" />
    <AiSimilarFindings
      :finding-id="findingId"
      @triaged="emit('triaged')"
      @open="emit('open', $event)"
    />
    <AiRuleGenerator
      :finding-id="findingId"
      :default-engine="secret ? 'gitleaks' : 'opengrep'"
    />
  </div>
</template>
