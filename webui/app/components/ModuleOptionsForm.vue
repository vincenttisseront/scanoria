<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Formulaire généré depuis le schéma d'options d'un module (G3) : valeurs par
défaut pré-remplies, aucun champ obligatoire, contrôle immédiat de chaque
valeur, retour au défaut d'un clic.
-->

<script setup lang="ts">
import { checkOption, cloneValue, optionDefaults, optionFields, type OptionField } from '#shared/module-options'

const props = defineProps<{
  schema: unknown
  i18n?: Record<string, unknown> | null
  disabled?: boolean
}>()
const model = defineModel<Record<string, unknown>>({ default: () => ({}) })
const emit = defineEmits<{ valid: [value: boolean] }>()

const { t, locale } = useI18n()
const fields = computed(() => optionFields(props.schema, props.i18n))

watch(fields, (list) => {
  const defaults = optionDefaults(list)
  const next: Record<string, unknown> = {}
  for (const f of list) next[f.key] = Object.hasOwn(model.value, f.key) ? model.value[f.key] : defaults[f.key]
  model.value = next
}, { immediate: true })

const issues = computed(() => Object.fromEntries(fields.value.map(f => [f.key, checkOption(f, model.value[f.key])])))
watch(issues, v => emit('valid', Object.values(v).every(c => c === null)), { immediate: true })

const label = (f: OptionField) => f.i18n?.[locale.value]?.title ?? f.title ?? f.key
const help = (f: OptionField) => f.i18n?.[locale.value]?.description ?? f.description ?? ''
const isDefault = (f: OptionField) => JSON.stringify(model.value[f.key]) === JSON.stringify(f.default)
const items = (f: OptionField) => (f.enum ?? []).map(v => ({ label: String(v), value: v }))

function set(key: string, value: unknown) {
  model.value = { ...model.value, [key]: value }
}
function reset(f: OptionField) {
  set(f.key, cloneValue(f.default))
}
function setList(f: OptionField, raw: string) {
  set(f.key, raw.split('\n').map(s => s.trim()).filter(Boolean))
}
</script>

<template>
  <p
    v-if="!fields.length"
    class="text-sm text-muted"
  >
    {{ t('catalog.options.none') }}
  </p>
  <div
    v-else
    class="grid gap-4 md:grid-cols-2"
  >
    <UFormField
      v-for="f in fields"
      :key="f.key"
      :label="label(f)"
      :description="help(f)"
      :error="issues[f.key] ? t(`catalog.options.errors.${issues[f.key]}`) : undefined"
      :data-option="f.key"
    >
      <div class="flex items-center gap-2">
        <USwitch
          v-if="f.type === 'boolean'"
          :model-value="model[f.key] === true"
          :disabled="disabled"
          @update:model-value="v => set(f.key, v)"
        />
        <USelect
          v-else-if="f.enum && f.type !== 'array'"
          :model-value="model[f.key] as string"
          :items="items(f)"
          :disabled="disabled"
          class="w-full"
          @update:model-value="v => set(f.key, v)"
        />
        <UInputNumber
          v-else-if="f.type === 'integer' || f.type === 'number'"
          :model-value="model[f.key] as number"
          :min="f.minimum"
          :max="f.maximum"
          :step="f.type === 'integer' ? 1 : 0.1"
          :disabled="disabled"
          class="w-full"
          @update:model-value="v => set(f.key, v)"
        />
        <UTextarea
          v-else-if="f.type === 'array'"
          :model-value="Array.isArray(model[f.key]) ? (model[f.key] as string[]).join('\n') : ''"
          :placeholder="t('catalog.options.onePerLine')"
          :rows="3"
          :disabled="disabled"
          class="w-full"
          @update:model-value="v => setList(f, String(v))"
        />
        <UInput
          v-else
          :model-value="model[f.key] as string"
          :disabled="disabled"
          class="w-full"
          @update:model-value="v => set(f.key, v)"
        />
        <UButton
          v-if="!isDefault(f) && !disabled"
          icon="i-lucide-rotate-ccw"
          color="neutral"
          variant="ghost"
          size="xs"
          :aria-label="t('catalog.options.reset')"
          @click="reset(f)"
        />
      </div>
    </UFormField>
  </div>
</template>
