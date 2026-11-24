<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Tableau de bord minimal : santé lue dans l'état publié par le service root.
-->

<script setup lang="ts">
const { t, te } = useI18n()
useHead({ title: computed(() => t('dashboard.title')) })

const session = useSession()
const fmt = useFormat()
const { data, state, failed, loading, refresh } = useApplianceState()
const selftest = useHelperRequest()
const diag = useApplianceDiagnosis()
const quick = ref(true)

type BadgeColor = 'success' | 'warning' | 'error' | 'neutral' | 'info'
function statusColor(s: string | undefined): BadgeColor {
  if (s === 'active' || s === 'pass') return 'success'
  if (s === 'warn' || s === 'activating' || s === 'deactivating') return 'warning'
  if (s === 'failed' || s === 'fail') return 'error'
  return 'neutral'
}
function statusLabel(s: string | undefined): string {
  return s && te(`status.${s}`) ? t(`status.${s}`) : t('status.unknown')
}

const tlsDaysLeft = computed(() => {
  const end = state.value?.tls.not_after
  return end ? Math.floor((Date.parse(end) - Date.now()) / 86_400_000) : null
})
const tlsColor = computed<BadgeColor>(() => {
  const d = tlsDaysLeft.value
  if (d === null) return 'neutral'
  if (d < 0) return 'error'
  return d <= 14 ? 'warning' : 'success'
})

async function runSelftest() {
  await selftest.run('/api/system/selftest', { quick: quick.value })
  await refresh()
  await diag.refresh()
}
</script>

<template>
  <PageShell :title="t('dashboard.title')">
    <template #actions>
      <UButton
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="ghost"
        :loading="loading"
        :aria-label="t('common.refresh')"
        @click="refresh"
      />
    </template>

    <StateAlert
      :data="data"
      :failed="failed"
    />
    <SbomExposureBanner />
    <VigilanceBanner />
    <div
      v-if="diag.alerts.value.length"
      class="space-y-2"
    >
      <AiApplianceDiagnosis
        v-for="s in diag.alerts.value"
        :key="s"
        :subject-id="s"
        compact
      />
    </div>

    <div
      v-if="!data && loading"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="state">
      <p class="text-xs text-muted">
        {{ t('state.generatedAt', { date: fmt.date(state.generated_at) }) }}
      </p>

      <UAlert
        v-if="state.helper.busy && state.helper.current"
        color="info"
        variant="subtle"
        icon="i-lucide-loader-circle"
        :title="t('dashboard.helperBusy', { type: state.helper.current.type })"
        :description="te(`steps.${state.helper.current.step}`) ? t(`steps.${state.helper.current.step}`) : state.helper.current.step"
        :ui="{ icon: 'animate-spin' }"
      />

      <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.appliance') }}
            </h2>
          </template>
          <dl class="space-y-1 text-sm">
            <div class="flex justify-between gap-2">
              <dt class="text-muted">
                {{ t('dashboard.fqdn') }}
              </dt>
              <dd class="font-mono">
                {{ state.appliance.fqdn ?? '—' }}
              </dd>
            </div>
            <div class="flex justify-between gap-2">
              <dt class="text-muted">
                {{ t('dashboard.version') }}
              </dt>
              <dd>{{ state.appliance.version }}</dd>
            </div>
            <div class="flex justify-between gap-2">
              <dt class="text-muted">
                {{ t('dashboard.previousVersion') }}
              </dt>
              <dd>{{ state.appliance.previous_version ?? t('common.none') }}</dd>
            </div>
            <div class="flex justify-between gap-2">
              <dt class="text-muted">
                {{ t('dashboard.resources') }}
              </dt>
              <dd>{{ t('dashboard.cpuMemory', { cpu: state.appliance.cpu_count, memory: state.appliance.memory_mb }) }}</dd>
            </div>
          </dl>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.services') }}
            </h2>
          </template>
          <ul class="space-y-1 text-sm">
            <li
              v-for="(s, name) in state.services"
              :key="name"
              class="flex justify-between gap-2"
            >
              <span class="font-mono">{{ name }}</span>
              <UBadge
                :color="statusColor(s)"
                variant="subtle"
                :label="statusLabel(s)"
              />
            </li>
          </ul>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.disks') }}
            </h2>
          </template>
          <ul class="space-y-3 text-sm">
            <li
              v-for="d in state.disks"
              :key="d.mount"
            >
              <div class="flex justify-between">
                <span class="font-mono">{{ d.mount }}</span>
                <span class="text-muted">{{ t('dashboard.diskFree', { avail: fmt.gb(d.avail_mb), size: fmt.gb(d.size_mb) }) }}</span>
              </div>
              <UProgress
                :model-value="d.size_mb ? Math.round(100 * (d.size_mb - d.avail_mb) / d.size_mb) : 0"
                :color="d.size_mb && d.avail_mb / d.size_mb < 0.1 ? 'warning' : 'primary'"
                size="sm"
              />
            </li>
          </ul>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.tls') }}
            </h2>
          </template>
          <div class="space-y-2 text-sm">
            <UBadge
              :color="tlsColor"
              variant="subtle"
              :label="t(`tls.modes.${state.tls.mode}`)"
            />
            <p v-if="state.tls.not_after">
              {{ t('dashboard.tlsExpires', { date: fmt.date(state.tls.not_after) }) }}
            </p>
            <p class="text-muted">
              {{ t('dashboard.firewall') }} :
              {{ state.firewall.loaded ? t('dashboard.firewallLoaded') : t('dashboard.firewallNotLoaded') }}
            </p>
          </div>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.update') }}
            </h2>
          </template>
          <div class="space-y-2 text-sm">
            <UBadge
              v-if="state.update.available && state.update.latest_version"
              color="info"
              variant="subtle"
              :label="t('dashboard.updateAvailable', { version: state.update.latest_version })"
            />
            <UBadge
              v-else
              color="success"
              variant="subtle"
              :label="t('dashboard.upToDate')"
            />
            <p class="text-muted">
              {{ state.update.last_check_at ? t('updates.lastCheck', { date: fmt.date(state.update.last_check_at) }) : t('updates.neverChecked') }}
            </p>
            <UButton
              to="/updates"
              variant="link"
              :label="t('nav.updates')"
              trailing-icon="i-lucide-arrow-right"
              class="px-0"
            />
          </div>
        </UCard>

        <UCard>
          <template #header>
            <h2 class="font-semibold">
              {{ t('dashboard.selftest') }}
            </h2>
          </template>
          <div class="space-y-3 text-sm">
            <div v-if="state.selftest">
              <UBadge
                :color="statusColor(state.selftest.status)"
                variant="subtle"
                :label="statusLabel(state.selftest.status)"
              />
              <p class="mt-1 text-muted">
                {{ t('dashboard.selftestLast', { date: fmt.date(state.selftest.finished_at) }) }}
              </p>
            </div>
            <p
              v-else
              class="text-muted"
            >
              {{ t('dashboard.selftestNever') }}
            </p>
            <div
              v-if="session.can('admin')"
              class="flex flex-wrap items-center gap-3"
            >
              <UButton
                icon="i-lucide-stethoscope"
                :loading="selftest.running.value"
                :label="t('dashboard.runSelftest')"
                @click="runSelftest"
              />
              <UCheckbox
                v-model="quick"
                :disabled="selftest.running.value"
                :label="t('dashboard.runQuick')"
              />
            </div>
            <RequestProgress
              :active="selftest.running.value"
              :label="selftest.label.value"
            />
            <AiApplianceDiagnosis
              v-if="!selftest.running.value && diag.has('selftest:last')"
              subject-id="selftest:last"
              compact
            />
          </div>
        </UCard>
      </div>
    </template>
  </PageShell>
</template>
