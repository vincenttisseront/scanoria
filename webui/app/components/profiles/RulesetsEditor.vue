<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Jeux de règles d'un profil (G4, G8) : attacher un jeu de règles géré, le
détacher, le suivre sur sa dernière version ou l'épingler sur une version.
La liste vient de GET /api/rulesets (chantier A) ; l'enregistrement passe par
le PATCH du profil, avec ses contrôles et son audit.
-->

<script setup lang="ts">
interface RulesetItem { id: string, slug: string, engine: string, name: string, latest_version: number | null, archived_at: string | null }

const props = defineProps<{ disabled?: boolean, known?: { ruleset_id: string, slug: string, engine: string }[] }>()
const model = defineModel<RulesetAttachment[]>({ required: true })
const { t } = useI18n()
const { api, errorMessage } = useApi()

const LATEST = '__latest__'
const items = ref<RulesetItem[]>([])
const loading = ref(true)
const loadError = ref('')
onMounted(async () => {
  try {
    items.value = (await api<{ items: RulesetItem[] }>('/api/rulesets')).items.filter(r => !r.archived_at)
  }
  catch (err) {
    loadError.value = errorMessage(err)
  }
  finally {
    loading.value = false
  }
})

const byId = computed(() => new Map(items.value.map(r => [r.id, r])))
const label = (id: string) => {
  const r = byId.value.get(id)
  if (r) return { slug: r.slug, engine: r.engine }
  const k = props.known?.find(x => x.ruleset_id === id)
  return k ? { slug: k.slug, engine: k.engine } : { slug: id, engine: '' }
}
const addable = computed(() => items.value
  .filter(r => r.latest_version !== null && !model.value.some(a => a.ruleset_id === r.id))
  .map(r => ({ label: `${r.slug} (${r.engine})`, value: r.id })))
const adding = ref<string | undefined>(undefined)
function add(id: string | undefined) {
  if (!id) return
  model.value = [...model.value, { ruleset_id: id, pinned_version: null }]
  adding.value = undefined
}
function remove(id: string) {
  model.value = model.value.filter(a => a.ruleset_id !== id)
}
function versionItems(id: string) {
  const max = byId.value.get(id)?.latest_version ?? 0
  return [
    { label: t('profiles.rulesetsEditor.latest'), value: LATEST },
    ...Array.from({ length: max }, (_, i) => max - i).map(v => ({ label: t('profiles.rulesetsEditor.version', { n: v }), value: String(v) })),
  ]
}
function setVersion(id: string, v: string) {
  model.value = model.value.map(a => (a.ruleset_id === id ? { ...a, pinned_version: v === LATEST ? null : Number(v) } : a))
}
</script>

<template>
  <div
    class="space-y-3"
    data-testid="rulesets-editor"
  >
    <p class="text-sm text-muted">
      {{ t('profiles.rulesetsEditor.help') }}
    </p>
    <div
      v-if="loading"
      class="flex items-center gap-2 text-sm text-muted"
      data-testid="rulesets-loading"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('profiles.rulesetsEditor.loading') }}
    </div>
    <UAlert
      v-else-if="loadError"
      color="error"
      variant="subtle"
      :title="loadError"
    />
    <p
      v-if="!model.length"
      class="text-sm text-muted"
    >
      {{ t('profiles.rulesetsEditor.none') }}
    </p>
    <ul
      v-else
      class="divide-y divide-default rounded-md border border-default"
    >
      <li
        v-for="a in model"
        :key="a.ruleset_id"
        class="flex flex-wrap items-center gap-3 px-3 py-2"
        :data-testid="`ruleset-${label(a.ruleset_id).slug}`"
      >
        <NuxtLink
          :to="`/rulesets/${a.ruleset_id}`"
          class="font-mono text-sm hover:underline"
        >{{ label(a.ruleset_id).slug }}</NuxtLink>
        <UBadge
          v-if="label(a.ruleset_id).engine"
          color="neutral"
          variant="subtle"
          :label="label(a.ruleset_id).engine"
        />
        <USelect
          :model-value="a.pinned_version === null ? LATEST : String(a.pinned_version)"
          :items="versionItems(a.ruleset_id)"
          class="ms-auto w-44"
          :disabled="disabled || !byId.has(a.ruleset_id)"
          @update:model-value="(v: string) => setVersion(a.ruleset_id, v)"
        />
        <UButton
          icon="i-lucide-x"
          color="neutral"
          variant="ghost"
          :aria-label="t('profiles.rulesetsEditor.remove')"
          :disabled="disabled"
          data-testid="ruleset-remove"
          @click="remove(a.ruleset_id)"
        />
      </li>
    </ul>
    <USelectMenu
      v-if="!disabled && !loading && !loadError"
      :model-value="adding"
      :items="addable"
      value-key="value"
      :placeholder="t('profiles.rulesetsEditor.add')"
      class="w-full sm:w-80"
      data-testid="ruleset-add"
      @update:model-value="(v: string | undefined) => add(v)"
    />
  </div>
</template>
