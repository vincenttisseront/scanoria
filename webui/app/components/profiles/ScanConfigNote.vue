<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Sur la page d'une analyse (G8, G9, J8) : profil effectif figé dans le plan
(héritage, déclencheur, origine du choix) et état de .scanoria.yml au moment
de l'analyse. Un fichier invalide est signalé ; la configuration précédente
a alors été appliquée. Les chemins ignorés sont notés dans la couverture.
-->

<script setup lang="ts">
interface RepoConfigNote { status: 'ok' | 'absent' | 'invalid' | 'unavailable', key: string | null, issues: { path: string, message: string }[], ignored: string[], profile: string | null }
interface PlanProfileNote { slug?: string, chain?: string[], slot?: string, source?: string }

const props = defineProps<{ repoConfig?: RepoConfigNote | null, profile?: PlanProfileNote | null }>()
const { t, te } = useI18n()

const chain = computed(() => props.profile?.chain?.length ? props.profile.chain.join(' › ') : props.profile?.slug ?? '')
const slotLabel = computed(() => (props.profile?.slot && te(`profiles.slots.${props.profile.slot}`) ? t(`profiles.slots.${props.profile.slot}`) : ''))
const sourceLabel = computed(() => (props.profile?.source && te(`profiles.scan.source.${props.profile.source}`) ? t(`profiles.scan.source.${props.profile.source}`) : ''))
</script>

<template>
  <div
    v-if="chain || (repoConfig && repoConfig.status !== 'absent')"
    class="mb-2 space-y-1 text-sm"
    data-testid="scan-config-note"
  >
    <p
      v-if="chain"
      class="text-muted"
    >
      {{ t('profiles.scan.profile') }} <span class="font-mono">{{ chain }}</span>
      <template v-if="slotLabel">
        · {{ slotLabel }}
      </template>
      <template v-if="sourceLabel">
        · {{ sourceLabel }}
      </template>
    </p>
    <UAlert
      v-if="repoConfig && (repoConfig.status === 'invalid' || repoConfig.status === 'unavailable')"
      :color="repoConfig.status === 'invalid' ? 'error' : 'warning'"
      variant="subtle"
      icon="i-lucide-file-warning"
      :title="t(`profiles.scan.config.${repoConfig.status}`)"
      data-testid="scan-config-invalid"
    >
      <template
        v-if="repoConfig.issues.length"
        #description
      >
        <ul class="list-disc ps-5 font-mono text-xs">
          <li
            v-for="(i, n) in repoConfig.issues"
            :key="n"
          >
            {{ i.path }} {{ i.message }}
          </li>
        </ul>
      </template>
    </UAlert>
    <p
      v-else-if="repoConfig && repoConfig.status === 'ok'"
      class="text-muted"
    >
      {{ t('profiles.scan.config.ok') }}
    </p>
    <div v-if="repoConfig && repoConfig.ignored.length">
      <p class="font-medium">
        {{ t('profiles.scan.ignored') }}
      </p>
      <ul class="list-disc pl-5 font-mono text-xs text-muted">
        <li
          v-for="p in repoConfig.ignored"
          :key="p"
        >
          {{ p }}
        </li>
      </ul>
    </div>
  </div>
</template>
