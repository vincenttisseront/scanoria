<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Verrous d'un profil (G8, contrat 28) : catégories et modules exigés, plancher
de quality gate règle par règle, « aucun envoi à l'IA ». Les verrous hérités
des profils parents sont affichés à côté et ne peuvent pas être assouplis ;
la console signale tout de suite une valeur plus souple (le serveur la refuse).
-->

<script setup lang="ts">
import { CATEGORIES, GateRules, SEVERITIES, type ProfileLocks } from '#shared/analysis'

const props = defineProps<{ inherited: ProfileLocks, disabled?: boolean }>()
const locks = defineModel<ProfileLocks>({ required: true })
const { t, te } = useI18n()

const fields = gateFields().filter(f => f.kind !== 'locked')
const defaults = GateRules.parse({})
const NONE = '__none__'
const floor = computed(() => locks.value.gate_floor as Record<string, unknown>)
const inheritedFloor = computed(() => props.inherited.gate_floor as Record<string, unknown>)

const categoryItems = computed(() => CATEGORIES.map(c => ({ label: te(`findings.categories.${c}`) ? t(`findings.categories.${c}`) : c, value: c })))
const severityItems = computed(() => [
  ...SEVERITIES.map(s => ({ label: t(`gates.severities.${s}`), value: s })),
  { label: t('gates.none'), value: NONE },
])

function isSet(key: string): boolean {
  return key in floor.value && floor.value[key] !== undefined
}
function toggle(key: string, on: boolean) {
  const next = Object.fromEntries(Object.entries(floor.value).filter(([k]) => k !== key))
  if (on) next[key] = inheritedFloor.value[key] !== undefined ? inheritedFloor.value[key] : (defaults as Record<string, unknown>)[key]
  locks.value = { ...locks.value, gate_floor: next as ProfileLocks['gate_floor'] }
}
function setValue(key: string, v: unknown) {
  locks.value = { ...locks.value, gate_floor: { ...floor.value, [key]: v } as ProfileLocks['gate_floor'] }
}
function severityValue(key: string): string {
  return floor.value[key] === null ? NONE : String(floor.value[key])
}

/** Champs plus souples qu'un verrou hérité (même logique que le serveur). */
const SEV_RANK: Record<string, number> = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]))
function looser(key: string): boolean {
  const locked = inheritedFloor.value[key]
  if (locked === undefined || !isSet(key)) return false
  const v = floor.value[key]
  switch (key) {
    case 'new_code_only': return v === true && locked === false
    case 'license_denied_blocks':
    case 'kev_blocks': return v === false && locked === true
    case 'quarantine_days': return (v as number) < (locked as number)
    case 'vuln_block_from':
    case 'sast_block_from':
    case 'iac_block_from': {
      const r = (x: unknown) => (x === null ? Infinity : SEV_RANK[x as string] ?? Infinity)
      // SEVERITIES va de critical à info : un rang plus petit est plus souple.
      return r(v) === Infinity ? r(locked) !== Infinity : r(locked) !== Infinity && r(v) < r(locked)
    }
    default: {
      const n = (x: unknown) => (x === null ? Infinity : x as number)
      return n(v) > n(locked)
    }
  }
}
</script>

<template>
  <div class="space-y-5">
    <div class="grid gap-4 sm:grid-cols-2">
      <UFormField
        :label="t('profiles.locks.requiredCategories')"
        :help="t('profiles.locks.requiredCategoriesHelp')"
      >
        <USelectMenu
          :model-value="locks.required_categories"
          :items="categoryItems"
          value-key="value"
          multiple
          class="w-full"
          :disabled="disabled"
          data-testid="locks-categories"
          @update:model-value="(v: string[]) => locks = { ...locks, required_categories: v as ProfileLocks['required_categories'] }"
        />
        <p
          v-if="inherited.required_categories.length"
          class="mt-1 text-xs text-muted"
        >
          {{ t('profiles.locks.inherited') }} {{ inherited.required_categories.join(', ') }}
        </p>
      </UFormField>
      <UFormField
        :label="t('profiles.locks.requiredModules')"
        :help="t('profiles.locks.requiredModulesHelp')"
      >
        <UInputTags
          :model-value="locks.required_modules"
          class="w-full"
          :disabled="disabled"
          data-testid="locks-modules"
          @update:model-value="(v: string[]) => locks = { ...locks, required_modules: v.map(x => x.trim().toLowerCase()).filter(Boolean) }"
        />
        <p
          v-if="inherited.required_modules.length"
          class="mt-1 text-xs text-muted"
        >
          {{ t('profiles.locks.inherited') }} {{ inherited.required_modules.join(', ') }}
        </p>
      </UFormField>
    </div>

    <div>
      <h3 class="text-sm font-medium">
        {{ t('profiles.locks.floor') }}
      </h3>
      <p class="text-sm text-muted">
        {{ t('profiles.locks.floorHelp') }}
      </p>
      <div class="mt-3 divide-y divide-default rounded-md border border-default">
        <div
          v-for="f in fields"
          :key="f.key"
          class="flex flex-wrap items-center gap-3 px-3 py-2"
          :data-testid="`floor-${f.key}`"
        >
          <UCheckbox
            :model-value="isSet(f.key)"
            :disabled="disabled"
            :label="t(`gates.fields.${f.key}`)"
            class="min-w-56 flex-1"
            @update:model-value="(v: boolean | 'indeterminate') => toggle(f.key, v === true)"
          />
          <template v-if="isSet(f.key)">
            <USwitch
              v-if="f.kind === 'boolean'"
              :model-value="floor[f.key] === true"
              :disabled="disabled"
              @update:model-value="(v: boolean) => setValue(f.key, v)"
            />
            <USelect
              v-else-if="f.kind === 'severity'"
              :model-value="severityValue(f.key)"
              :items="severityItems"
              class="w-40"
              :disabled="disabled"
              @update:model-value="(v: string) => setValue(f.key, v === NONE ? null : v)"
            />
            <div
              v-else-if="f.kind === 'number'"
              class="flex items-center gap-2"
            >
              <UInputNumber
                :model-value="typeof floor[f.key] === 'number' ? floor[f.key] as number : undefined"
                :min="f.min"
                :step="f.key === 'epss_block_from' ? 0.01 : 1"
                :disabled="disabled || floor[f.key] === null"
                class="w-32"
                @update:model-value="(v: number | null | undefined) => setValue(f.key, v ?? f.min)"
              />
              <UCheckbox
                v-if="f.nullable"
                :model-value="floor[f.key] === null"
                :disabled="disabled"
                :label="t('profiles.locks.inactive')"
                @update:model-value="(v: boolean | 'indeterminate') => setValue(f.key, v === true ? null : f.min || 1)"
              />
            </div>
          </template>
          <UBadge
            v-if="inheritedFloor[f.key] !== undefined"
            color="neutral"
            variant="subtle"
            icon="i-lucide-lock"
            :label="`${t('profiles.locks.inheritedShort')} ${lockValueLabel(inheritedFloor[f.key], t, te)}`"
          />
          <UBadge
            v-if="looser(f.key)"
            color="error"
            variant="subtle"
            icon="i-lucide-triangle-alert"
            :label="t('profiles.locks.looser')"
          />
        </div>
      </div>
    </div>

    <div class="space-y-1">
      <USwitch
        :model-value="locks.ai_opt_out || inherited.ai_opt_out"
        :disabled="disabled || inherited.ai_opt_out"
        :label="t('profiles.locks.aiOptOut')"
        :description="inherited.ai_opt_out ? t('profiles.locks.aiOptOutInherited') : t('profiles.locks.aiOptOutHelp')"
        data-testid="locks-ai"
        @update:model-value="(v: boolean) => locks = { ...locks, ai_opt_out: v }"
      />
    </div>
  </div>
</template>
