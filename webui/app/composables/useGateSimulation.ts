// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// F9 et I19 : lance une simulation de quality gate, puis interroge son état
// jusqu'au résultat quand elle continue en tâche de fond. Indicateur
// d'attente (running) et rafraîchissement sans recharger la page.

export interface SimulationItem {
  scan_id: string
  project_slug: string
  number: number
  ref: string
  trigger: string
  tag: string | null
  release: boolean
  finished_at: string
  actual: string | null
  replay: string
  simulated: string
  effect: 'blocked' | 'unblocked' | 'unchanged'
  rules: string[]
}
export interface SimulationResult {
  since: string
  rules: Record<string, unknown>
  changed_rules: string[]
  scans: { total: number, blocked: number, unblocked: number, unchanged: number, drift: number, errors: number }
  releases: { total: number, blocked: number, unblocked: number, unchanged: number }
  by_rule: { rule: string, blocked: number, unblocked: number }[]
  items: SimulationItem[]
  truncated: boolean
  limited: boolean
}
export interface SimulationRow {
  id: string
  project_id: string | null
  gate_id: string | null
  rules: Record<string, unknown>
  since: string
  origin: 'manual' | 'ai'
  status: 'pending' | 'done' | 'error'
  result: SimulationResult | null
  created_at: string
}

/** Clés triées : deux jeux de règles égaux donnent la même chaîne. */
export function rulesKey(rules: Record<string, unknown> | null | undefined): string {
  if (!rules) return ''
  return JSON.stringify(Object.keys(rules).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).map(k => [k, rules[k]]))
}

export function useGateSimulation(pollMs = 2000) {
  const { api, errorMessage } = useApi()
  const simulation = ref<SimulationRow | null>(null)
  const running = ref(false)
  const error = ref('')
  let timer: ReturnType<typeof setTimeout> | null = null
  let disposed = false

  function clear() {
    if (timer) clearTimeout(timer)
    timer = null
  }

  async function follow(row: SimulationRow) {
    simulation.value = row
    clear()
    if (row.status !== 'pending' || disposed) {
      running.value = false
      return
    }
    running.value = true
    timer = setTimeout(async () => {
      try {
        await follow(await api<SimulationRow>(`/api/gates/simulations/${row.id}`))
      }
      catch (err) {
        running.value = false
        error.value = errorMessage(err)
      }
    }, pollMs)
  }

  async function run(body: { gate_id?: string, project_id?: string, rules: Record<string, unknown>, since_days: number }) {
    running.value = true
    error.value = ''
    try {
      await follow(await api<SimulationRow>('/api/gates/simulations', { method: 'POST', body }))
    }
    catch (err) {
      running.value = false
      error.value = errorMessage(err)
    }
  }

  onBeforeUnmount(() => {
    disposed = true
    clear()
  })

  return { simulation, running, error, run, follow }
}
