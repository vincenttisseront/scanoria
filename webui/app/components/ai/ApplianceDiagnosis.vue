<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Diagnostic IA de l'appliance (I16) : cause probable, explication en clair et
une action proposée parmi celles de la console, sous forme de lien vers la
page qui porte le bouton. Rien n'est fait automatiquement. Affiché à côté
d'une alerte, du selftest, d'une mise à jour ou d'un module, pour les
administrateurs seulement ; rien sans connecteur (cadre AiTaskPanel).
-->

<script setup lang="ts">
const props = withDefaults(defineProps<{ subjectId: string, compact?: boolean }>(), { compact: false })
const { t } = useI18n()
const session = useSession()

const ACTION_PAGES: Record<string, (module: string | null) => string | null> = {
  'rerun-selftest': () => '/',
  'check-update': () => '/updates',
  'retry-update': () => '/updates',
  'rollback-update': () => '/updates',
  'import-update': () => '/updates',
  'retry-install': m => (m ? `/catalog/${m}` : null),
  'update-module': m => (m ? `/catalog/${m}` : null),
  'uninstall-module': m => (m ? `/catalog/${m}` : null),
  'renew-certificate': () => '/system/tls',
  'check-dns': () => '/catalog/dns',
  'check-admin-networks': () => '/system',
  'check-ai-connector': () => '/system/ai',
  'view-scan-health': () => '/scans/health',
}

const title = computed(() => {
  const [kind, ...rest] = props.subjectId.split(':')
  const key = rest.join(':')
  let what = ''
  if (kind === 'alert' && key === 'update-rollback') what = t('ai.appliance.subjects.updateRollback')
  else if (kind === 'alert' && key === 'tls-expiry') what = t('ai.appliance.subjects.tlsExpiry')
  else if (kind === 'alert' && key.startsWith('service:')) what = t('ai.appliance.subjects.service', { name: key.slice(8) })
  else if (kind === 'alert' && key.startsWith('disk:')) what = t('ai.appliance.subjects.disk', { mount: key.slice(5) === 'root' ? '/' : `/${key.slice(5)}` })
  else if (kind === 'selftest') what = t('ai.appliance.subjects.selftest')
  else if (kind === 'update') what = t('ai.appliance.subjects.update', { id: key })
  else if (kind === 'install') what = t('ai.appliance.subjects.install', { module: key })
  return what ? `${t('ai.appliance.title')} : ${what}` : t('ai.appliance.title')
})
const list = (v: unknown) => (Array.isArray(v) ? v as string[] : [])
function actionLink(output: Record<string, unknown>): string | null {
  const action = String(output.action ?? 'none')
  const module = typeof output.module === 'string' ? output.module : null
  return ACTION_PAGES[action]?.(module) ?? null
}
</script>

<template>
  <AiTaskPanel
    v-if="session.can('admin')"
    kind="diagnose-appliance"
    api-path="/api/ai/appliance/diagnosis"
    :subject-id="props.subjectId"
    :title="title"
    :ask-label="t('ai.appliance.ask')"
    :compact="compact"
    icon="i-lucide-stethoscope"
  >
    <template #default="{ output }">
      <div
        class="space-y-2"
        data-testid="ai-appliance-diagnosis"
      >
        <div class="flex flex-wrap items-center gap-2">
          <span class="text-muted">{{ t('ai.appliance.cause') }}</span>
          <UBadge
            color="warning"
            variant="subtle"
            :label="t(`ai.appliance.causes.${String(output.cause)}`)"
          />
        </div>
        <p>{{ output.summary }}</p>
        <p class="text-muted">
          {{ output.explanation }}
        </p>
        <div v-if="list(output.steps).length">
          <h4 class="text-xs font-semibold uppercase text-muted">
            {{ t('ai.appliance.steps') }}
          </h4>
          <ol class="list-decimal ps-5">
            <li
              v-for="(s, i) in list(output.steps)"
              :key="i"
            >
              {{ s }}
            </li>
          </ol>
        </div>
        <div
          v-if="output.action && output.action !== 'none'"
          class="flex flex-wrap items-center gap-2 rounded-md bg-elevated p-2"
          data-testid="ai-appliance-action"
        >
          <span>{{ t('ai.appliance.proposed', { action: t(`ai.appliance.actions.${String(output.action)}`) }) }}</span>
          <span class="text-muted">{{ output.action_reason }}</span>
          <UButton
            v-if="actionLink(output)"
            size="xs"
            variant="outline"
            trailing-icon="i-lucide-arrow-right"
            :to="actionLink(output)!"
            :label="t('ai.appliance.goTo')"
          />
        </div>
        <p class="text-xs text-muted">
          {{ t('ai.appliance.noAutomaticAction') }}
        </p>
      </div>
    </template>
  </AiTaskPanel>
</template>
