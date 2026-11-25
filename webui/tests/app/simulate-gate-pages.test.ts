// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.8) : F9, simulateur de quality gate sur la page du gate
// (résultat, tâche de fond suivie sans recharger, règles changées depuis) ;
// I19, seuils suggérés par l'IA (simulés d'emblée, page du gate préremplie,
// enregistrement audité « proposé par IA »).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import GatePage from '~/pages/gates/[id].vue'
import GatesSuggestion from '~/components/gates/Suggestion.vue'
import GatesSimulationResult from '~/components/gates/SimulationResult.vue'
import { GateRules } from '#shared/analysis'
import { rulesKey } from '~/composables/useGateSimulation'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const GATE = '11111111-1111-4111-8111-111111111111'
const PROJECT = '33333333-3333-4333-8333-333333333333'
const SCAN = '66666666-6666-4666-8666-666666666666'
const TASK = '77777777-7777-4777-8777-777777777777'
const SIM = '55555555-5555-4555-8555-555555555555'
const RULES = GateRules.parse({})

const detail = () => ({
  id: GATE, slug: 'defaut', builtin: true, rules: RULES, updated_at: '2026-11-24T08:00:00Z', updated_by_username: null,
  project_list: [{ id: PROJECT, slug: 'alpha', name: 'Alpha' }],
})

function result(rules: Record<string, unknown>) {
  return {
    since: '2026-08-27T00:00:00Z', rules, changed_rules: ['sast_block_from'],
    scans: { total: 4, blocked: 2, unblocked: 0, unchanged: 2, drift: 1, errors: 1 },
    releases: { total: 1, blocked: 1, unblocked: 0, unchanged: 0 },
    by_rule: [{ rule: 'sast_block_from', blocked: 2, unblocked: 0 }, { rule: 'kev_blocks', blocked: 1, unblocked: 0 }],
    items: [
      { scan_id: SCAN, project_slug: 'alpha', number: 7, ref: 'v1.2.0', trigger: 'release', tag: 'v1.2.0', release: true, finished_at: '2026-11-20T10:00:00Z', actual: 'passed', replay: 'passed', simulated: 'failed', effect: 'blocked', rules: ['sast_block_from'] },
      { scan_id: '88888888-8888-4888-8888-888888888888', project_slug: 'alpha', number: 6, ref: 'main', trigger: 'manual', tag: null, release: false, finished_at: '2026-11-19T10:00:00Z', actual: 'passed', replay: 'passed', simulated: 'passed', effect: 'unchanged', rules: [] },
    ],
    truncated: true, limited: true,
  }
}
const row = (rules: Record<string, unknown>, patch: Record<string, unknown> = {}) => ({
  id: SIM, project_id: null, gate_id: GATE, rules, since: '2026-08-27T00:00:00Z', origin: 'manual', status: 'done', created_at: '2026-11-25T08:00:00Z', result: result(rules), ...patch,
})

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

describe('F9 : simulation sur la page du gate', () => {
  it('clés de règles stables quel que soit l’ordre', () => {
    expect(rulesKey({ b: 1, a: 2 })).toBe(rulesKey({ a: 2, b: 1 }))
    expect(rulesKey(null)).toBe('')
  })

  it('tâche de fond suivie jusqu’au résultat, effet détaillé, règles changées depuis signalées', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      setUser('admin')
      route('GET', `/api/gates/${GATE}`, () => detail())
      let polls = 0
      route('POST', '/api/gates/simulations', (_e, body) => row((body as { rules: Record<string, unknown> }).rules, { status: 'pending', result: null }))
      route('GET', `/api/gates/simulations/${SIM}`, () => {
        polls++
        return polls < 2 ? row(RULES, { status: 'pending', result: null }) : row(RULES)
      })
      await mountIn(GatePage, { route: `/gates/${GATE}` })
      await settle()
      await click(document.body.querySelector('[data-testid="gate-simulate"]')!)
      expect(document.body.querySelector('[data-testid="simulation-running"]')).not.toBeNull()
      await vi.advanceTimersByTimeAsync(2100)
      await settle()
      await vi.advanceTimersByTimeAsync(2100)
      await settle()
      expect(polls).toBe(2)
      const text = bodyText()
      expect(text).toContain('Analyses rejouées : 4')
      expect(text).toContain('Releases : 1')
      expect(text).toContain('2 bloquée(s)')
      expect(text).toContain('1 verdict(s) réel(s) différent(s) du rejeu')
      expect(text).toContain('1 analyse(s) non rejouée(s)')
      expect(text).toContain('période limitée')
      expect(text).toContain('Résultats SAST bloquants à partir de')
      expect(text).toContain('Vulnérabilité exploitée activement (KEV) bloquante')
      expect(text).toContain('alpha · n° 7')
      expect(text).toContain('Liste abrégée')
      // Règles inchangées depuis : enregistrement impossible (rien à enregistrer).
      expect(document.body.querySelector<HTMLButtonElement>('[data-testid="gate-save"]')!.disabled).toBe(true)
      // Une modification rend la simulation périmée.
      await click(document.body.querySelector('[data-testid="rule-new_code_only"] button[role="switch"]')!)
      expect(bodyText()).toContain('Les règles du formulaire ont changé depuis cette simulation')
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('erreur de simulation affichée ; simulation en erreur signalée', async () => {
    setUser('operator')
    route('GET', `/api/gates/${GATE}`, () => detail())
    let fail = true
    route('POST', '/api/gates/simulations', () => (fail ? apiFail(400, 'E_VALIDATION') : row(RULES, { status: 'error', result: null })))
    await mountIn(GatePage, { route: `/gates/${GATE}` })
    await settle()
    expect(document.body.querySelector('[data-testid="gate-save"]')).toBeNull()
    await click(document.body.querySelector('[data-testid="gate-simulate"]')!)
    expect(document.body.querySelector('[data-testid="simulation-result"]')).toBeNull()
    fail = false
    await click(document.body.querySelector('[data-testid="gate-simulate"]')!)
    expect(bodyText()).toContain('La simulation a échoué.')
  })

  it('lecteur : pas de simulation', async () => {
    setUser('viewer')
    route('GET', `/api/gates/${GATE}`, () => detail())
    await mountIn(GatePage, { route: `/gates/${GATE}` })
    await settle()
    expect(document.body.querySelector('[data-testid="gate-simulation"]')).toBeNull()
  })

  it('résultat sans effet', async () => {
    const r = row(RULES)
    r.result = { ...r.result, by_rule: [], items: [], truncated: false, limited: false }
    await mountIn(GatesSimulationResult, { props: { simulation: r } })
    await settle()
    expect(bodyText()).toContain('Ces règles ne changent aucun verdict sur la période.')
  })
})

describe('I19 : seuils suggérés', () => {
  const suggested = { ...RULES, sast_block_from: 'critical' }

  it('page du gate préremplie, simulée d’emblée, enregistrement avec ai_task_id', async () => {
    setUser('admin')
    route('GET', `/api/gates/${GATE}`, () => detail())
    route('GET', `/api/gates/suggestions/${TASK}`, () => ({ task_id: TASK, project_id: PROJECT, gate_id: GATE, gate_slug: 'defaut', rules: suggested, rationale: 'Moins de blocages SAST.', exceptions: [], model: 'qwen-test:14b', model_digest: 'a'.repeat(64) }))
    route('POST', '/api/gates/simulations', (_e, body) => row((body as { rules: Record<string, unknown> }).rules))
    route('PATCH', `/api/gates/${GATE}`, () => detail())
    await mountIn(GatePage, { route: `/gates/${GATE}?ai_task=${TASK}` })
    await settle()
    expect(document.body.querySelector('[data-testid="gate-ai-prefill"]')!.textContent).toContain('qwen-test:14b')
    expect(callsTo('POST', '/api/gates/simulations')[0]!.body).toMatchObject({ rules: suggested })
    await click(document.body.querySelector('[data-testid="gate-save"]')!)
    expect(bodyText()).toContain('« proposé par IA »')
    await click(button('Enregistrer'))
    expect(callsTo('PATCH', `/api/gates/${GATE}`)[0]!.body).toEqual({ rules: suggested, ai_task_id: TASK })
  })

  it('proposition d’un autre gate ou indisponible : signalée, rien prérempli', async () => {
    setUser('admin')
    route('GET', `/api/gates/${GATE}`, () => detail())
    route('GET', `/api/gates/suggestions/${TASK}`, () => ({ task_id: TASK, gate_id: PROJECT, rules: suggested, rationale: 'x', model: null }))
    await mountIn(GatePage, { route: `/gates/${GATE}?ai_task=${TASK}` })
    await settle()
    expect(bodyText()).toContain('Cette proposition concerne un autre gate.')
    clearBody()
    resetApi()
    route('GET', `/api/gates/${GATE}`, () => detail())
    route('GET', `/api/gates/suggestions/${TASK}`, () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(GatePage, { route: `/gates/${GATE}?ai_task=${TASK}` })
    await settle()
    expect(bodyText()).toContain('La proposition de l’IA n’est plus disponible.')
  })

  const output = {
    rules: { new_code_only: true, max_secrets: 0, vuln_block_from: 'high', sast_block_from: 'critical', iac_block_from: 'none' },
    rationale: 'Le SAST bloque trop souvent.',
    exceptions: [{ tool: 'semgrep', rule_id: 'javascript.audit.regexp', reason: 'Règle bruyante.', expires_in_days: 30 }],
  }
  const aiOutput = () => ({ enabled: true, opt_out: false, task: { id: TASK, status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: 'a'.repeat(64), generated_at: '2026-11-25T09:00:00Z', output, feedback: null } })

  it('panneau du projet : proposition, simulation automatique une fois, lien vers le gate', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', aiOutput)
    route('POST', `/api/gates/projects/${PROJECT}/suggestion/simulate`, () => ({ task_id: TASK, gate_id: GATE, gate_slug: 'defaut', rules: suggested, simulation: { ...row(suggested), origin: 'ai', project_id: PROJECT } }))
    await mountIn(GatesSuggestion, { props: { projectId: PROJECT } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Le SAST bloque trop souvent.')
    expect(text).toContain('critique')
    expect(text).toContain('Ne bloque jamais')
    expect(text).toContain('javascript.audit.regexp')
    expect(text).toContain('30 jours')
    expect(text).toContain('Analyses rejouées : 4')
    expect(callsTo('POST', `/api/gates/projects/${PROJECT}/suggestion/simulate`)).toHaveLength(1)
    expect(document.body.querySelector('[data-testid="gate-suggestion-open"]')!.getAttribute('href')).toBe(`/gates/${GATE}?ai_task=${TASK}`)
  })

  it('simulation indisponible signalée', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', aiOutput)
    route('POST', `/api/gates/projects/${PROJECT}/suggestion/simulate`, () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(GatesSuggestion, { props: { projectId: PROJECT } })
    await settle()
    expect(bodyText()).toContain('La simulation de cette proposition n’est pas disponible.')
    expect(document.body.querySelector('[data-testid="gate-suggestion-open"]')).toBeNull()
  })

  it('sans connecteur : rien', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', () => ({ enabled: false, opt_out: false, task: null }))
    await mountIn(GatesSuggestion, { props: { projectId: PROJECT } })
    await settle()
    expect(document.body.querySelector('[data-testid="gate-suggestion"]')).toBeNull()
    expect(callsTo('POST', `/api/gates/projects/${PROJECT}/suggestion/simulate`)).toHaveLength(0)
  })
})
