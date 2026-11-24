<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Explication d'une licence de composant (I18), à placer à côté de la décision
de licence (F8) : obligations principales, compatibilité avec la licence du
projet, conditions à vérifier. Marquée « proposé par IA » et « aide, pas un
avis juridique ». Seuls les identifiants des deux licences sont envoyés. La
clé est calculée par le serveur ; rien n'apparaît sans connecteur ni pour un
projet « aucun envoi à l'IA ».
-->

<script setup lang="ts">
const props = defineProps<{ license: string, projectId: string }>()
const { t } = useI18n()
const { api } = useApi()
const key = ref<string | null>(null)
const list = (v: unknown) => (Array.isArray(v) ? v as string[] : [])

async function loadKey() {
  try {
    key.value = (await api<{ key: string | null }>('/api/ai/license-key', { query: { license: props.license, project_id: props.projectId } })).key
  }
  catch {
    key.value = null
  }
}
watch(() => [props.license, props.projectId], loadKey)
onMounted(loadKey)
</script>

<template>
  <AiTaskPanel
    v-if="key"
    kind="explain-license"
    :subject-id="key"
    :title="t('ai.license.title')"
    icon="i-lucide-scale"
    compact
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-license"
      >
        <p>{{ output.summary }}</p>
        <UBadge
          color="neutral"
          variant="subtle"
          :label="t(`ai.license.compatibility.${String(output.compatibility)}`)"
        />
        <p class="text-xs">
          {{ output.compatibility_note }}
        </p>
        <div v-if="list(output.obligations).length">
          <p class="text-xs text-muted">
            {{ t('ai.license.obligations') }}
          </p>
          <ul class="list-disc ps-5 text-xs">
            <li
              v-for="(o, i) in list(output.obligations)"
              :key="i"
            >
              {{ o }}
            </li>
          </ul>
        </div>
        <div v-if="list(output.to_check).length">
          <p class="text-xs text-muted">
            {{ t('ai.license.toCheck') }}
          </p>
          <ul class="list-disc ps-5 text-xs">
            <li
              v-for="(o, i) in list(output.to_check)"
              :key="i"
            >
              {{ o }}
            </li>
          </ul>
        </div>
        <p
          class="text-xs font-medium"
          data-testid="ai-license-not-legal"
        >
          {{ t('ai.license.notLegal') }}
        </p>
      </div>
    </template>
  </AiTaskPanel>
</template>
