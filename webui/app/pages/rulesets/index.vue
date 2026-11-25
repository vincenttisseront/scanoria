<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Vincent Tisseront

Jeux de règles gérés (G4) : liste par moteur, règles maison de l'appliance
en lecture seule (copie pour modifier), création et import. L'import d'un
jeu Semgrep rappelle les conditions de la Semgrep Rules License.
-->

<script setup lang="ts">
const { t } = useI18n()
useHead({ title: computed(() => t('rulesets.title')) })

const { api, errorMessage } = useApi()
const session = useSession()
const toast = useToast()
const fmt = useFormat()
const isAdmin = computed(() => session.can('admin'))

const ENGINES = ['opengrep', 'semgrep', 'gitleaks', 'checkov', 'kics'] as const
type Engine = (typeof ENGINES)[number]

interface Row {
  id: string
  slug: string
  engine: Engine
  name: string
  description: string | null
  archived_at: string | null
  latest_version: number | null
  latest_origin: 'manual' | 'import' | 'ai' | null
  latest_at: string | null
  profiles: number
}
interface Builtin { slug: string, engine: Engine, license: string, sha256: string, content: string, rules: number }

const rows = ref<Row[]>([])
const builtin = ref<Builtin[]>([])
const loading = ref(false)
const showArchived = ref(false)

async function load() {
  loading.value = true
  try {
    const [list, base] = await Promise.all([
      api<{ items: Row[] }>('/api/rulesets', { query: showArchived.value ? { archived: '1' } : {} }),
      api<{ items: Builtin[] }>('/api/rulesets/builtin'),
    ])
    rows.value = list.items
    builtin.value = base.items
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    loading.value = false
  }
}
onMounted(load)
watch(showArchived, load)

const engineItems = computed(() => ENGINES.map(e => ({ label: t(`rulesets.engines.${e}`), value: e })))

// ------------------------------------------------------------ voir les règles maison
const viewing = ref<Builtin | null>(null)
const viewOpen = computed({ get: () => viewing.value !== null, set: (v) => {
  if (!v) viewing.value = null
} })

// ------------------------------------------------------------ création / import
const createOpen = ref(false)
const creating = ref(false)
const form = reactive({
  mode: 'manual' as 'manual' | 'import',
  slug: '',
  engine: 'opengrep' as Engine,
  name: '',
  description: '',
  content: '',
  comment: '',
  licenseAck: false,
})
const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,62}$/
const needsAck = computed(() => form.mode === 'import' && form.engine === 'semgrep')
const canCreate = computed(() => SLUG_RE.test(form.slug) && form.slug !== 'scanoria-base' && form.name.trim() && form.content.trim()
  && (!needsAck.value || form.licenseAck))

function openCreate(mode: 'manual' | 'import', from?: Builtin) {
  Object.assign(form, {
    mode, slug: from ? 'scanoria-base-copie' : '', engine: from?.engine ?? 'opengrep', name: from ? t('rulesets.builtin.title') : '',
    description: '', content: from?.content ?? '', comment: '', licenseAck: false,
  })
  createOpen.value = true
}

async function readFileInput(ev: Event) {
  const file = (ev.target as HTMLInputElement).files?.[0]
  if (!file) return
  if (file.size > 1024 * 1024) {
    toast.add({ title: t('codes.E_TOO_LARGE'), color: 'error' })
    return
  }
  form.content = await file.text()
  if (!form.slug) form.slug = file.name.toLowerCase().replace(/\.[a-z0-9]+$/, '').replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63)
  if (!form.name) form.name = file.name.slice(0, 200)
}

async function create() {
  creating.value = true
  try {
    const res = await api<{ id: string }>('/api/rulesets', {
      method: 'POST',
      body: {
        slug: form.slug, engine: form.engine, name: form.name.trim(), description: form.description.trim() || null,
        content: form.content, comment: form.comment.trim() || null, origin: form.mode,
        ...(needsAck.value ? { license_ack: form.licenseAck } : {}),
      },
    })
    toast.add({ title: t('rulesets.create.created'), color: 'success' })
    createOpen.value = false
    await navigateTo(`/rulesets/${res.id}`)
  }
  catch (err) {
    toast.add({ title: errorMessage(err), color: 'error' })
  }
  finally {
    creating.value = false
  }
}
</script>

<template>
  <PageShell :title="t('rulesets.title')">
    <template #actions>
      <UButton
        icon="i-lucide-refresh-cw"
        color="neutral"
        variant="ghost"
        :loading="loading"
        :aria-label="t('common.refresh')"
        @click="load"
      />
      <template v-if="isAdmin">
        <UButton
          icon="i-lucide-upload"
          color="neutral"
          variant="outline"
          :label="t('rulesets.create.import')"
          data-testid="ruleset-import"
          @click="openCreate('import')"
        />
        <UButton
          icon="i-lucide-plus"
          :label="t('rulesets.create.action')"
          data-testid="ruleset-new"
          @click="openCreate('manual')"
        />
      </template>
    </template>

    <p class="text-sm text-muted">
      {{ t('rulesets.help') }}
    </p>
    <UAlert
      v-if="!isAdmin"
      color="neutral"
      variant="subtle"
      icon="i-lucide-lock"
      :title="t('rulesets.readOnly')"
    />

    <UCard
      v-for="b in builtin"
      :key="b.slug"
      data-testid="ruleset-builtin"
    >
      <div class="flex flex-wrap items-start justify-between gap-3">
        <div class="space-y-1">
          <h2 class="font-semibold">
            {{ t('rulesets.builtin.title') }}
            <span class="font-mono text-xs text-muted">{{ b.slug }}</span>
          </h2>
          <p class="text-sm text-muted">
            {{ t('rulesets.builtin.help') }}
          </p>
          <p class="text-xs text-muted">
            {{ t(`rulesets.engines.${b.engine}`) }} · {{ b.license }} · {{ t('rulesets.builtin.rules', { n: b.rules }) }}
          </p>
        </div>
        <div class="flex gap-2">
          <UButton
            size="sm"
            color="neutral"
            variant="outline"
            icon="i-lucide-eye"
            :label="t('rulesets.builtin.view')"
            @click="viewing = b"
          />
          <UButton
            v-if="isAdmin"
            size="sm"
            icon="i-lucide-copy"
            :label="t('rulesets.builtin.copy')"
            data-testid="ruleset-builtin-copy"
            @click="openCreate('manual', b)"
          />
        </div>
      </div>
    </UCard>

    <div class="flex justify-end">
      <USwitch
        v-model="showArchived"
        :label="t('rulesets.showArchived')"
      />
    </div>

    <UCard>
      <div
        v-if="loading && !rows.length"
        class="flex justify-center py-6"
        role="status"
      >
        <UIcon
          name="i-lucide-loader-circle"
          class="size-6 animate-spin"
        />
      </div>
      <p
        v-else-if="!rows.length"
        class="text-sm text-muted"
      >
        {{ t('rulesets.none') }}
      </p>
      <table
        v-else
        class="w-full text-sm"
      >
        <thead>
          <tr class="text-left text-muted">
            <th class="py-1 font-normal">
              {{ t('rulesets.create.name') }}
            </th>
            <th class="py-1 font-normal">
              {{ t('rulesets.engine') }}
            </th>
            <th class="py-1 font-normal">
              {{ t('rulesets.detail.version') }}
            </th>
            <th class="py-1 font-normal">
              {{ t('rulesets.profiles.title') }}
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="r in rows"
            :key="r.id"
            class="border-t border-default"
            :data-testid="`ruleset-${r.slug}`"
          >
            <td class="py-2">
              <NuxtLink
                :to="`/rulesets/${r.id}`"
                class="font-medium hover:underline"
              >{{ r.name }}</NuxtLink>
              <span class="ml-2 font-mono text-xs text-muted">{{ r.slug }}</span>
              <UBadge
                v-if="r.archived_at"
                class="ml-2"
                color="neutral"
                variant="subtle"
                :label="t('rulesets.archived')"
              />
            </td>
            <td class="py-2">
              {{ t(`rulesets.engines.${r.engine}`) }}
            </td>
            <td class="py-2">
              <span v-if="r.latest_version">
                {{ t('rulesets.latest', { version: r.latest_version }) }}
                <span class="text-xs text-muted">· {{ t(`rulesets.origins.${r.latest_origin}`) }} · {{ fmt.date(r.latest_at) }}</span>
              </span>
              <span
                v-else
                class="text-muted"
              >{{ t('rulesets.noVersion') }}</span>
            </td>
            <td class="py-2">
              {{ t('rulesets.profilesCount', { n: r.profiles }) }}
            </td>
          </tr>
        </tbody>
      </table>
    </UCard>

    <UModal
      v-model:open="viewOpen"
      :title="t('rulesets.builtin.title')"
      :ui="{ content: 'max-w-4xl' }"
    >
      <template #body>
        <pre class="max-h-[60vh] overflow-auto rounded-md bg-elevated p-3 text-xs"><code>{{ viewing?.content }}</code></pre>
      </template>
    </UModal>

    <UModal
      v-model:open="createOpen"
      :title="form.mode === 'import' ? t('rulesets.create.importTitle') : t('rulesets.create.title')"
      :dismissible="!creating"
      :ui="{ content: 'max-w-3xl' }"
    >
      <template #body>
        <div class="space-y-4">
          <div class="grid gap-4 sm:grid-cols-2">
            <UFormField :label="t('rulesets.engine')">
              <USelect
                v-model="form.engine"
                :items="engineItems"
                class="w-full"
                data-testid="ruleset-engine"
              />
            </UFormField>
            <UFormField
              :label="t('rulesets.create.slug')"
              :help="t('rulesets.create.slugHelp')"
            >
              <UInput
                v-model="form.slug"
                class="w-full font-mono"
                data-testid="ruleset-slug"
              />
            </UFormField>
          </div>
          <UFormField :label="t('rulesets.create.name')">
            <UInput
              v-model="form.name"
              class="w-full"
              data-testid="ruleset-name"
            />
          </UFormField>
          <UFormField :label="t('rulesets.create.description')">
            <UInput
              v-model="form.description"
              class="w-full"
            />
          </UFormField>
          <UFormField
            v-if="form.mode === 'import'"
            :label="t('rulesets.create.file')"
          >
            <input
              type="file"
              accept=".yaml,.yml,.toml,.json,.txt"
              class="text-sm"
              data-testid="ruleset-file"
              @change="readFileInput"
            >
          </UFormField>
          <UFormField
            :label="t('rulesets.create.content')"
            :help="t(`rulesets.formats.${form.engine}`)"
          >
            <UTextarea
              v-model="form.content"
              :rows="12"
              class="w-full font-mono text-xs"
              data-testid="ruleset-content"
            />
          </UFormField>
          <UFormField :label="t('rulesets.create.comment')">
            <UInput
              v-model="form.comment"
              class="w-full"
            />
          </UFormField>
          <UAlert
            v-if="needsAck"
            color="warning"
            icon="i-lucide-scale"
            :title="t('rulesets.semgrepLicense.title')"
            :description="t('rulesets.semgrepLicense.body')"
            data-testid="semgrep-license"
          />
          <UCheckbox
            v-if="needsAck"
            v-model="form.licenseAck"
            :label="t('rulesets.semgrepLicense.ack')"
            data-testid="semgrep-license-ack"
          />
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="ghost"
            :disabled="creating"
            :label="t('common.cancel')"
            @click="createOpen = false"
          />
          <UButton
            :loading="creating"
            :disabled="!canCreate"
            :label="t('common.create')"
            data-testid="ruleset-create-confirm"
            @click="create"
          />
        </div>
      </template>
    </UModal>
  </PageShell>
</template>
