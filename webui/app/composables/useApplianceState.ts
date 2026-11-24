// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// État publié par le service root (lecture seule), rafraîchi périodiquement.

export interface ApplianceState {
  generated_at: string
  appliance: {
    fqdn: string | null
    version: string
    previous_version: string | null
    firstboot_done: boolean
    cpu_count: number
    memory_mb: number
  }
  helper: {
    busy: boolean
    current: { id: string, type: string, step: string, started_at: string } | null
    queue_length: number
  }
  update: {
    channel: 'stable' | 'prerelease'
    auto_check: boolean
    auto_apply: boolean
    maintenance_window: { days: string[], start: string, duration_minutes: number } | null
    last_check_at: string | null
    last_check_code?: string | null
    latest_version: string | null
    /** Version abandonnée par un retour à N-1 : jamais réinstallée automatiquement. */
    skipped_version?: string | null
    available: boolean
    notes_md?: string | null
    published_at?: string | null
    source_url?: string | null
    /** Alerte permanente après un échec du retour arrière (E_ROLLBACK_FAILED). */
    alert?: { code: 'E_ROLLBACK_FAILED', message: string, at: string, version?: string } | null
  }
  tls: {
    mode: 'internal' | 'imported' | 'none'
    subject_alt_names: string[]
    not_before?: string | null
    not_after: string | null
    fingerprint_sha256: string | null
    ca_fingerprint_sha256: string | null
    ca_not_after?: string | null
  }
  firewall: { loaded: boolean, admin_networks: string[] }
  services: Record<string, string>
  disks: { mount: string, size_mb: number, avail_mb: number }[]
  selftest?: { status: 'pass' | 'warn' | 'fail', finished_at: string } | null
}

export interface StateResponse {
  available: boolean
  reason?: 'missing' | 'invalid' | 'stale'
  age_seconds?: number
  state: ApplianceState | null
  console_version: string
}

export function useApplianceState(refreshMs = 30_000) {
  const { api } = useApi()
  const data = ref<StateResponse | null>(null)
  // Compteur : un rafraîchissement manuel et le poll peuvent se chevaucher, le
  // spinner reste affiché jusqu'à la fin du dernier.
  const inflight = ref(0)
  const loading = computed(() => inflight.value > 0)
  // Échec du dernier appel : sans lui, une erreur réseau laissait une page vide.
  const failed = ref(false)
  let timer: ReturnType<typeof setInterval> | undefined

  async function refresh(): Promise<void> {
    inflight.value++
    try {
      data.value = await api<StateResponse>('/api/state')
      failed.value = false
    }
    catch {
      failed.value = true
    }
    finally {
      inflight.value--
    }
  }

  onMounted(() => {
    void refresh()
    timer = setInterval(() => void refresh(), refreshMs)
  })
  onBeforeUnmount(() => {
    if (timer) clearInterval(timer)
  })

  const state = computed(() => data.value?.state ?? null)
  return { data, state, loading, failed, refresh }
}
