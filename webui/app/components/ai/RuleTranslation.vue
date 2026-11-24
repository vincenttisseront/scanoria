<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Traduction du texte de la règle (I17), en français seulement : l'anglais
d'origine des outils reste affiché à côté, et la clé de la règle est
calculée par le serveur. Rien pour un secret ou un projet exclu.
-->

<script setup lang="ts">
const props = defineProps<{ findingId: string, original: string }>()
const { t, locale } = useI18n()
const { api } = useApi()

const key = ref<string | null>(null)
async function load() {
  key.value = null
  if (locale.value !== 'fr') return
  try {
    key.value = (await api<{ key: string | null }>('/api/ai/rule-key', { query: { finding_id: props.findingId } })).key
  }
  catch {
    key.value = null
  }
}
watch(() => [props.findingId, locale.value], load)
onMounted(load)
</script>

<template>
  <AiTaskPanel
    v-if="key"
    kind="translate-rule"
    :subject-id="key"
    :title="t('ai.translation.title')"
    icon="i-lucide-languages"
    auto-ask
    compact
  >
    <template #default="{ output }">
      <div
        class="space-y-1"
        data-testid="ai-translation"
      >
        <p>{{ output.translation }}</p>
        <p class="text-xs text-muted">
          {{ t('ai.translation.original') }} : {{ original }}
        </p>
      </div>
    </template>
  </AiTaskPanel>
</template>
