<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Composants (F3) : « qui utilise tel composant, telle version, tel CVE ? »
dans le dernier SBOM de chaque projet. Résultats groupés par projet, page
suivante par curseur, export CSV de toute la recherche. Indicateur d'attente
pendant la recherche, sans rechargement de la page.
-->

<script setup lang="ts">
interface LinkedFinding { id: string, tool: string, severity: string, status: string, vuln_ids: string[], title: string }
interface ComponentHit {
  purl: string
  ecosystem: string
  name: string
  version: string | null
  licenses: string[]
  direct: boolean | null
  published_at: string | null
  findings: LinkedFinding[]
}
interface ProjectHit {
  project: { id: string, slug: string, name: string, archived: boolean }
  scan: { id: string, number: number, ref: string, finished_at: string | null }
  components: ComponentHit[]
}
interface SearchResult { items: ProjectHit[], next_cursor: string | null, total_projects: number, total_components: number, truncated: boolean }

const { t } = useI18n()
useHead({ title: computed(() => t('components.title')) })
const { api, errorMessage } = useApi()
const fmt = useFormat()
const route = useRoute()
const router = useRouter()

/** Valeur « tous » du sélecteur (un élément de liste ne peut pas valoir « »). */
const ANY = 'any'
const ECOSYSTEMS = ['npm', 'pypi', 'maven', 'golang', 'cargo', 'gem', 'nuget', 'composer', 'deb', 'rpm', 'apk']
const form = reactive({
  query: typeof route.query.q === 'string' ? route.query.q : '',
  ecosystem: typeof route.query.ecosystem === 'string' ? route.query.ecosystem : ANY,
  version_from: typeof route.query.from === 'string' ? route.query.from : '',
  version_to: typeof route.query.to === 'string' ? route.query.to : '',
  vuln: typeof route.query.vuln === 'string' ? route.query.vuln : '',
})
const ecosystemItems = computed(() => [{ label: t('components.anyEcosystem'), value: ANY }, ...ECOSYSTEMS.map(e => ({ label: e, value: e }))])

const loading = ref(false)
const loadingMore = ref(false)
const error = ref<string | null>(null)
const result = ref<SearchResult | null>(null)

/** Paramètres de l'API : un purl est cherché tel quel, sinon par nom. */
const params = computed(() => {
  const p: Record<string, string> = {}
  const q = form.query.trim()
  if (q.startsWith('pkg:')) p.purl = q
  else if (q) p.name = q
  if (form.ecosystem && form.ecosystem !== ANY) p.ecosystem = form.ecosystem
  if (form.version_from.trim()) p.version_from = form.version_from.trim()
  if (form.version_to.trim()) p.version_to = form.version_to.trim()
  if (form.vuln.trim()) p.vuln = form.vuln.trim().toUpperCase()
  return p
})
const canSearch = computed(() => !!(params.value.purl || params.value.name || params.value.vuln))
/** Critères de la dernière recherche : « Plus » et l'export CSV s'y tiennent, même si le formulaire a changé depuis. */
const searched = ref<Record<string, string>>({})
const csvHref = computed(() => `/api/components/export.csv?${new URLSearchParams(searched.value).toString()}`)

async function search() {
  if (!canSearch.value) return
  loading.value = true
  error.value = null
  try {
    const query = { ...params.value }
    result.value = await api<SearchResult>('/api/components', { query })
    searched.value = query
    void router.replace({ query: { q: form.query || undefined, ecosystem: form.ecosystem !== ANY ? form.ecosystem : undefined, from: form.version_from || undefined, to: form.version_to || undefined, vuln: form.vuln || undefined } })
  }
  catch (err) {
    error.value = errorMessage(err)
    result.value = null
  }
  finally {
    loading.value = false
  }
}

async function more() {
  if (!result.value?.next_cursor) return
  loadingMore.value = true
  try {
    const next = await api<SearchResult>('/api/components', { query: { ...searched.value, cursor: result.value.next_cursor } })
    result.value = { ...next, items: [...result.value.items, ...next.items] }
  }
  catch (err) {
    error.value = errorMessage(err)
  }
  finally {
    loadingMore.value = false
  }
}

onMounted(() => {
  if (canSearch.value) void search()
})
</script>

<template>
  <PageShell :title="t('components.title')">
    <p class="text-sm text-muted">
      {{ t('components.help') }}
    </p>

    <UCard>
      <form
        class="grid gap-3 md:grid-cols-6"
        data-testid="components-form"
        @submit.prevent="search"
      >
        <UFormField
          :label="t('components.query')"
          class="md:col-span-2"
        >
          <UInput
            v-model="form.query"
            :placeholder="t('components.queryPlaceholder')"
            class="w-full"
            data-testid="components-query"
          />
        </UFormField>
        <UFormField :label="t('components.ecosystem')">
          <USelect
            v-model="form.ecosystem"
            :items="ecosystemItems"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('components.versionFrom')">
          <UInput
            v-model="form.version_from"
            placeholder="1.0.0"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('components.versionTo')">
          <UInput
            v-model="form.version_to"
            placeholder="1.2.5"
            class="w-full"
          />
        </UFormField>
        <UFormField :label="t('components.vuln')">
          <UInput
            v-model="form.vuln"
            placeholder="CVE-2021-44906"
            class="w-full"
            data-testid="components-vuln"
          />
        </UFormField>
        <div class="flex flex-wrap items-center gap-2 md:col-span-6">
          <UButton
            type="submit"
            icon="i-lucide-search"
            :label="t('components.search')"
            :loading="loading"
            :disabled="!canSearch"
            data-testid="components-search"
          />
          <UButton
            v-if="result && result.total_components"
            :href="csvHref"
            external
            color="neutral"
            variant="outline"
            icon="i-lucide-download"
            :label="t('components.exportCsv')"
            data-testid="components-csv"
          />
          <span
            v-if="!canSearch"
            class="text-xs text-muted"
          >{{ t('components.needCriteria') }}</span>
        </div>
      </form>
    </UCard>

    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      icon="i-lucide-circle-alert"
      :title="error"
    />

    <div
      v-if="loading && !result"
      class="flex items-center gap-2 text-muted"
    >
      <UIcon
        name="i-lucide-loader-circle"
        class="size-4 animate-spin"
      />
      {{ t('app.loading') }}
    </div>

    <template v-if="result">
      <p
        class="text-sm text-muted"
        data-testid="components-summary"
      >
        {{ t('components.summary', { projects: result.total_projects, components: result.total_components }) }}
        <span v-if="result.truncated">{{ t('components.truncated') }}</span>
      </p>
      <UCard v-if="!result.items.length">
        <p class="text-sm text-muted">
          {{ t('components.none') }}
        </p>
      </UCard>
      <UCard
        v-for="hit in result.items"
        :key="hit.project.id"
        :data-testid="`components-project-${hit.project.slug}`"
      >
        <template #header>
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div class="flex items-center gap-2">
              <NuxtLink
                :to="`/projects/${hit.project.id}`"
                class="font-semibold hover:underline"
              >
                {{ hit.project.name }}
              </NuxtLink>
              <UBadge
                v-if="hit.project.archived"
                color="neutral"
                variant="subtle"
                size="sm"
              >
                {{ t('components.archived') }}
              </UBadge>
            </div>
            <NuxtLink
              :to="`/scans/${hit.scan.id}`"
              class="text-xs text-muted hover:underline"
            >
              {{ t('components.scan', { number: hit.scan.number, ref: hit.scan.ref }) }}
              <template v-if="hit.scan.finished_at">· {{ fmt.date(hit.scan.finished_at) }}</template>
            </NuxtLink>
          </div>
        </template>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-muted">
                <th class="py-1 font-normal">
                  {{ t('components.col.component') }}
                </th>
                <th class="py-1 font-normal">
                  {{ t('components.col.version') }}
                </th>
                <th class="py-1 font-normal">
                  {{ t('components.col.licenses') }}
                </th>
                <th class="py-1 font-normal">
                  {{ t('components.col.published') }}
                </th>
                <th class="py-1 font-normal">
                  {{ t('components.col.findings') }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="c in hit.components"
                :key="c.purl"
                class="border-t border-default align-top"
              >
                <td class="py-2">
                  <div class="font-medium">
                    {{ c.name }}
                    <UBadge
                      v-if="c.direct"
                      color="neutral"
                      variant="outline"
                      size="sm"
                    >
                      {{ t('components.direct') }}
                    </UBadge>
                  </div>
                  <div class="font-mono text-xs text-muted break-all">
                    {{ c.purl }}
                  </div>
                </td>
                <td class="py-2 font-mono text-xs">
                  {{ c.version ?? '—' }}
                </td>
                <td class="py-2 font-mono text-xs">
                  {{ c.licenses.length ? c.licenses.join(', ') : '—' }}
                </td>
                <td class="py-2 text-xs">
                  {{ c.published_at ? fmt.date(c.published_at) : t('components.unknownDate') }}
                </td>
                <td class="py-2">
                  <div
                    v-if="c.findings.length"
                    class="flex flex-col gap-1"
                  >
                    <NuxtLink
                      v-for="f in c.findings"
                      :key="f.id"
                      :to="{ path: '/findings', query: { project_id: hit.project.id, q: f.vuln_ids[0] ?? f.title, status: 'all' } }"
                      class="flex items-center gap-1 text-xs hover:underline"
                    >
                      <FindingsSeverityBadge :severity="f.severity" />
                      <span class="font-mono">{{ f.vuln_ids.slice(0, 2).join(', ') }}</span>
                      <span class="text-muted">({{ f.tool }})</span>
                    </NuxtLink>
                  </div>
                  <span
                    v-else
                    class="text-xs text-muted"
                  >—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </UCard>
      <div
        v-if="result.next_cursor"
        class="flex justify-center"
      >
        <UButton
          color="neutral"
          variant="outline"
          :label="t('components.more')"
          :loading="loadingMore"
          data-testid="components-more"
          @click="more"
        />
      </div>
    </template>
  </PageShell>
</template>
