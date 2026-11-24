<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Vigilance de l'appliance sur la page Mises à jour : dernier relevé des SBOM
de la console et des images des modules (F19), vulnérabilités ouvertes par
sujet, derniers canaris (G14). Relevé et canaris tournent seuls chaque jour
et chaque nuit ; un administrateur peut les relancer.
-->

<script setup lang="ts">
import { subjectName, type SelfVuln, type VigilanceSummary } from '~/utils/vigilance'

const emit = defineEmits<{ changed: [] }>()
const { t, te } = useI18n()
const { api, errorMessage } = useApi()
const fmt = useFormat()
const session = useSession()
const toast = useToast()
const data = ref<VigilanceSummary | null>(null)
const loading = ref(false)
const sbomReq = useHelperRequest()
const canaryReq = useHelperRequest()
const openSubject = ref<string | null>(null)
const vulns = ref<SelfVuln[]>([])
const vulnsLoading = ref(false)

async function load() {
  loading.value = true
  try {
    data.value = await api<VigilanceSummary>('/api/vigilance')
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)

async function runSelfSbom() {
  await sbomReq.run('/api/vigilance/self-sbom', {}, { timeoutMs: 60 * 60_000, pollMs: 5000 })
  await load()
  emit('changed')
}
async function runCanaries() {
  await canaryReq.run('/api/vigilance/canaries', {}, { timeoutMs: 60 * 60_000, pollMs: 5000 })
  await load()
  emit('changed')
}

async function toggle(subject: string) {
  if (openSubject.value === subject) {
    openSubject.value = null
    return
  }
  openSubject.value = subject
  vulnsLoading.value = true
  vulns.value = []
  try {
    vulns.value = (await api<{ vulns: SelfVuln[] }>('/api/vigilance/self-vulns', { query: { subject } })).vulns
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    vulnsLoading.value = false
  }
}

const vulnBy = computed(() => new Map((data.value?.vulns ?? []).map(v => [v.subject, v])))
const label = (s: string) => (s === 'console' ? t('vigilance.console') : subjectName(s))
const gapLabel = (g: string) => (te(`vigilance.gaps.${g}`) ? t(`vigilance.gaps.${g}`) : g)
const busy = computed(() => sbomReq.running.value || canaryReq.running.value)
</script>

<template>
  <UCard data-testid="vigilance-panel">
    <template #header>
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 class="font-semibold">
            {{ t('vigilance.panel.title') }}
          </h2>
          <p class="text-sm text-muted">
            {{ t('vigilance.panel.help') }}
          </p>
        </div>
        <div
          v-if="session.can('admin')"
          class="flex gap-2"
        >
          <UButton
            icon="i-lucide-scan-search"
            color="neutral"
            variant="subtle"
            :loading="sbomReq.running.value"
            :disabled="busy"
            :label="t('vigilance.panel.runSelfSbom')"
            @click="runSelfSbom"
          />
          <UButton
            icon="i-lucide-bird"
            color="neutral"
            variant="subtle"
            :loading="canaryReq.running.value"
            :disabled="busy"
            :label="t('vigilance.panel.runCanaries')"
            @click="runCanaries"
          />
        </div>
      </div>
    </template>

    <RequestProgress
      :active="sbomReq.running.value"
      :label="sbomReq.label.value"
    />
    <RequestProgress
      :active="canaryReq.running.value"
      :label="canaryReq.label.value"
    />
    <div
      v-if="loading && !data"
      class="flex items-center gap-2 text-sm text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="data">
      <p
        v-if="!data.self_sbom"
        class="text-sm text-muted"
      >
        {{ t('vigilance.panel.never') }}
      </p>
      <template v-else>
        <p class="text-sm">
          {{ t('vigilance.panel.lastRun', { date: fmt.date(data.self_sbom.at) }) }}
        </p>
        <ul
          v-if="data.self_sbom.gaps.length"
          class="mt-1 text-sm text-warning"
        >
          <li
            v-for="g in data.self_sbom.gaps"
            :key="g"
          >
            {{ gapLabel(g) }}
          </li>
        </ul>
        <table class="mt-3 w-full text-sm">
          <thead class="text-left text-muted">
            <tr>
              <th class="py-1">
                {{ t('vigilance.panel.subject') }}
              </th>
              <th>{{ t('vigilance.panel.components') }}</th>
              <th>{{ t('vigilance.panel.vulns') }}</th>
              <th>{{ t('vigilance.panel.update') }}</th>
            </tr>
          </thead>
          <tbody>
            <template
              v-for="s in data.self_sbom.subjects"
              :key="s.subject"
            >
              <tr class="border-t border-default">
                <td class="py-1">
                  <UButton
                    variant="link"
                    color="neutral"
                    class="p-0"
                    :icon="openSubject === s.subject ? 'i-lucide-chevron-down' : 'i-lucide-chevron-right'"
                    :label="`${label(s.subject)} ${s.version ?? ''}`"
                    @click="toggle(s.subject)"
                  />
                </td>
                <td>{{ s.error ? t('vigilance.panel.subjectError') : s.components }}</td>
                <td>
                  <template v-if="vulnBy.get(s.subject)">
                    {{ t('vigilance.panel.counts', vulnBy.get(s.subject)!) }}
                  </template>
                  <template v-else>
                    {{ s.tools.length && s.tools.every(x => x.ok) ? t('vigilance.panel.none') : t('vigilance.panel.incomplete') }}
                  </template>
                </td>
                <td>{{ vulnBy.get(s.subject)?.update_available ?? '—' }}</td>
              </tr>
              <tr v-if="openSubject === s.subject">
                <td
                  colspan="4"
                  class="pb-2"
                >
                  <div
                    v-if="vulnsLoading"
                    class="flex items-center gap-2 text-muted"
                  >
                    <UIcon
                      name="i-lucide-loader-circle"
                      class="size-4 animate-spin"
                    />
                    {{ t('app.loading') }}
                  </div>
                  <p
                    v-else-if="!vulns.length"
                    class="text-muted"
                  >
                    {{ t('vigilance.panel.none') }}
                  </p>
                  <ul
                    v-else
                    class="space-y-0.5 font-mono text-xs"
                  >
                    <li
                      v-for="v in vulns"
                      :key="`${v.vuln_id}|${v.purl}`"
                    >
                      {{ v.severity }} · {{ v.vuln_id }} · {{ v.purl }}
                      <span v-if="v.fixed_version">→ {{ v.fixed_version }}</span>
                    </li>
                  </ul>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </template>

      <h3 class="mt-4 text-sm font-semibold">
        {{ t('vigilance.panel.canaries') }}
      </h3>
      <p
        v-if="!data.canaries.latest.length"
        class="text-sm text-muted"
      >
        {{ t('vigilance.panel.noCanary') }}
      </p>
      <ul
        v-else
        class="text-sm"
      >
        <li
          v-for="c in data.canaries.latest"
          :key="c.module_id"
          class="flex items-center gap-2"
        >
          <UBadge
            :color="c.ok ? 'success' : 'error'"
            variant="subtle"
            :label="c.ok ? t('vigilance.canary.ok') : t('vigilance.canary.failed')"
          />
          <NuxtLink
            :to="`/catalog/${encodeURIComponent(c.module_id)}`"
            class="underline"
          >
            {{ c.module_id }} {{ c.module_version }}
          </NuxtLink>
          <span class="text-muted">{{ fmt.date(c.run_at) }}</span>
        </li>
      </ul>
    </template>
  </UCard>
</template>
