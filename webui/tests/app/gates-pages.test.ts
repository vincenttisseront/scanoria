// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Section Quality gates (chantier E) : liste et création par copie, formulaire
// généré depuis GateRules (H4 et G13 verrouillés), lecture seule hors admin,
// affectation et suppression ; intégration CI d'un projet (jeton montré une
// fois, révocation, badge) ; composant VerdictPanel.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { h } from 'vue'
import {
  apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser,
} from './helpers'
import GatesPage from '~/pages/gates/index.vue'
import GatePage from '~/pages/gates/[id].vue'
import CiPage from '~/pages/gates/projects/[id].vue'
import VerdictPanel from '~/components/gates/VerdictPanel.vue'
import { GateRules, type VerdictDetails } from '#shared/analysis'

const { toastAdd, navigateToMock } = vi.hoisted(() => ({ toastAdd: vi.fn(), navigateToMock: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))
mockNuxtImport('navigateTo', () => navigateToMock)

enableAutoUnmount(afterEach)

async function mount(...args: Parameters<typeof mountIn>) {
  const w = await mountIn(...args)
  await settle()
  return w
}

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  navigateToMock.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

const GATE = '11111111-1111-4111-8111-111111111111'
const OTHER = '22222222-2222-4222-8222-222222222222'
const PROJECT = '33333333-3333-4333-8333-333333333333'
const TOKEN = '44444444-4444-4444-8444-444444444444'
const RULES = GateRules.parse({})

const gateRow = (patch: Record<string, unknown> = {}) => ({
  id: GATE, slug: 'defaut', builtin: true, rules: RULES, created_at: '2026-11-24T08:00:00Z',
  updated_at: '2026-11-24T08:00:00Z', updated_by_username: null, projects: 2, ...patch,
})

describe('liste des gates', () => {
  it('affiche les gates et crée un gate par copie (admin)', async () => {
    setUser('admin')
    route('GET', '/api/gates', () => ({ items: [gateRow(), gateRow({ id: OTHER, slug: 'strict', builtin: false, updated_by_username: 'bob', projects: 0 })] }))
    route('POST', '/api/gates', () => gateRow({ id: OTHER, slug: 'nouveau', builtin: false }))
    await mount(GatesPage)
    expect(bodyText()).toContain('defaut')
    expect(bodyText()).toContain('intégré')
    expect(bodyText()).toContain('par bob')
    await click(button('Nouveau gate'))
    const input = document.body.querySelector<HTMLInputElement>('[data-testid="gate-slug"] input, input[data-testid="gate-slug"]')!
    input.value = 'nouveau'
    input.dispatchEvent(new Event('input'))
    await settle()
    await click(button('Créer'))
    expect(callsTo('POST', '/api/gates')[0]!.body).toEqual({ slug: 'nouveau', copy_from: GATE })
    expect(navigateToMock).toHaveBeenCalledWith(`/gates/${OTHER}`)
  })

  it('lecteur : pas de création ; erreur traduite', async () => {
    setUser('viewer')
    route('GET', '/api/gates', () => apiFail(500, 'E_INTERNAL'))
    await mount(GatesPage)
    expect(document.body.querySelector('[data-testid="gate-create"]')).toBeNull()
    // Erreur de chargement affichée dans la page (et non un simple toast fugitif).
    expect(document.body.textContent).toContain('Erreur interne de la console.')
  })
})

const simulationRow = (rules: Record<string, unknown>) => ({
  id: '55555555-5555-4555-8555-555555555555', project_id: null, gate_id: GATE, rules, since: '2026-08-27T00:00:00Z', origin: 'manual', status: 'done', created_at: '2026-11-25T08:00:00Z',
  result: {
    since: '2026-08-27T00:00:00Z', rules, changed_rules: ['new_code_only'],
    scans: { total: 0, blocked: 0, unblocked: 0, unchanged: 0, drift: 0, errors: 0 }, releases: { total: 0, blocked: 0, unblocked: 0, unchanged: 0 },
    by_rule: [], items: [], truncated: false, limited: false,
  },
})

describe('détail d’un gate', () => {
  const detail = (patch: Record<string, unknown> = {}) => ({ ...gateRow(), project_list: [{ id: PROJECT, slug: 'alpha', name: 'Alpha' }], locked: {}, ...patch })

  it('formulaire généré, H4 et G13 verrouillés avec leur raison, enregistrement', async () => {
    setUser('admin')
    route('GET', `/api/gates/${GATE}`, () => detail())
    route('PATCH', `/api/gates/${GATE}`, () => detail())
    route('POST', '/api/gates/simulations', (_e, body) => simulationRow((body as { rules: Record<string, unknown> }).rules))
    await mount(GatePage, { route: `/gates/${GATE}` })
    const text = bodyText()
    for (const label of ['Nouveau code seulement', 'Secrets tolérés', 'Vulnérabilités bloquantes à partir de', 'Paquet malveillant bloquant', 'Non concluant = bloquant']) {
      expect(text).toContain(label)
    }
    expect(text).toContain('Toujours actif (H4)')
    expect(text).toContain('Toujours actif (G13)')
    expect(document.body.querySelectorAll('[data-testid="rule-locked"]')).toHaveLength(2)
    expect(text).toContain('Alpha')
    const save = document.body.querySelector<HTMLButtonElement>('[data-testid="gate-save"]')!
    expect(save.disabled).toBe(true)
    // Bascule « nouveau code seulement » puis enregistre.
    const sw = document.body.querySelector<HTMLButtonElement>('[data-testid="rule-new_code_only"] button[role="switch"]')!
    await click(sw)
    // F9 : l'enregistrement attend une simulation des règles exactes du formulaire.
    expect(save.disabled).toBe(true)
    expect(bodyText()).toContain('Simulez ces règles avant de les enregistrer.')
    await click(document.body.querySelector<HTMLButtonElement>('[data-testid="gate-simulate"]')!)
    expect(callsTo('POST', '/api/gates/simulations')[0]!.body).toEqual({ gate_id: GATE, rules: { ...RULES, new_code_only: false }, since_days: 90 })
    expect(save.disabled).toBe(false)
    await click(save)
    expect(bodyText()).toContain('Enregistrer les règles')
    expect(callsTo('PATCH', `/api/gates/${GATE}`)).toHaveLength(0)
    await click(button('Enregistrer'))
    expect(callsTo('PATCH', `/api/gates/${GATE}`)[0]!.body).toEqual({ rules: { ...RULES, new_code_only: false } })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Règles enregistrées.' }))
  })

  it('lecteur : lecture seule, aucun bouton d’action', async () => {
    setUser('viewer')
    route('GET', `/api/gates/${GATE}`, () => detail())
    await mount(GatePage, { route: `/gates/${GATE}` })
    expect(bodyText()).toContain('Seul un administrateur peut modifier les règles.')
    expect(document.body.querySelector('[data-testid="gate-save"]')).toBeNull()
    expect(document.body.querySelector<HTMLButtonElement>('[data-testid="rule-new_code_only"] button[role="switch"]')!.disabled).toBe(true)
  })

  it('suppression confirmée dans une modale, erreur E_GATE_IN_USE traduite', async () => {
    setUser('admin')
    route('GET', `/api/gates/${OTHER}`, () => detail({ id: OTHER, slug: 'strict', builtin: false }))
    route('DELETE', `/api/gates/${OTHER}`, () => apiFail(409, 'E_GATE_IN_USE'))
    await mount(GatePage, { route: `/gates/${OTHER}` })
    await click(button('Supprimer'))
    expect(bodyText()).toContain('Supprimer ce quality gate ?')
    await click(button('Supprimer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Ce gate est encore affecté à un projet ou utilisé par une analyse.' }))
  })

  it('affectation : liste des projets indisponible signalée', async () => {
    setUser('admin')
    route('GET', `/api/gates/${GATE}`, () => detail())
    route('GET', '/api/projects', () => apiFail(404, 'E_NOT_FOUND'))
    await mount(GatePage, { route: `/gates/${GATE}` })
    await click(button('Affecter à un projet'))
    expect(bodyText()).toContain('La liste des projets n’est pas disponible.')
  })
})

describe('intégration CI d’un projet', () => {
  const info = (badge = false) => ({
    project: { id: PROJECT, slug: 'alpha', name: 'Alpha', archived: false, default_branch: 'main' },
    gate: { id: GATE, slug: 'defaut', builtin: true },
    badge: { enabled: badge, path: '/api/badges/alpha.svg' },
    active_tokens: 1,
  })
  const token = (patch: Record<string, unknown> = {}) => ({
    id: TOKEN, name: 'ci', prefix: 'scn_AbCd', created_at: '2026-11-24T08:00:00Z', created_by_username: 'alice',
    expires_at: null, last_used_at: null, revoked_at: null, ...patch,
  })

  it('jeton montré une seule fois, révocation confirmée, exemple de CI', async () => {
    setUser('operator')
    const value = `scn_${'x'.repeat(40)}`
    route('GET', `/api/gates/projects/${PROJECT}`, () => info())
    route('GET', `/api/projects/${PROJECT}/tokens`, () => ({ items: [token()] }))
    route('POST', `/api/projects/${PROJECT}/tokens`, () => ({ ...token(), value }))
    route('DELETE', `/api/projects/${PROJECT}/tokens/${TOKEN}`, () => token({ revoked_at: '2026-11-24T09:00:00Z' }))
    await mount(CiPage, { route: `/gates/projects/${PROJECT}` })
    expect(bodyText()).toContain('scn_AbCd…')
    expect(document.body.querySelector('[data-testid="project-id"]')!.textContent).toBe(PROJECT)
    expect(document.body.querySelector('[data-testid="ci-example"]')!.textContent).toContain(`--project ${PROJECT}`)
    expect(document.body.querySelector('[data-testid="ci-example"]')!.textContent).toContain('secrets.SCANORIA_TOKEN')

    await click(document.body.querySelector('[data-testid="token-create"]')!)
    await click(button('Créer'))
    expect(callsTo('POST', `/api/projects/${PROJECT}/tokens`)[0]!.body).toEqual({ name: 'ci', expires_in_days: null })
    expect(document.body.querySelector('[data-testid="token-value"]')!.textContent).toBe(value)
    expect(bodyText()).toContain('il ne sera plus jamais affiché')
    await click(button('Fermer'))
    expect(document.body.querySelector('[data-testid="token-value"]')).toBeNull()

    await click(button('Révoquer'))
    expect(bodyText()).toContain('Révoquer ce jeton ?')
    await click(button('Révoquer'))
    expect(callsTo('DELETE', `/api/projects/${PROJECT}/tokens/${TOKEN}`)).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Jeton révoqué.' }))
  })

  it('badge : activé par un opérateur, image affichée', async () => {
    setUser('operator')
    let enabled = false
    route('GET', `/api/gates/projects/${PROJECT}`, () => info(enabled))
    route('GET', `/api/projects/${PROJECT}/tokens`, () => ({ items: [] }))
    route('PUT', `/api/badges/projects/${PROJECT}`, (_e, body) => {
      enabled = (body as { enabled: boolean }).enabled
      return { enabled }
    })
    await mount(CiPage, { route: `/gates/projects/${PROJECT}` })
    expect(bodyText()).toContain('Aucun jeton pour ce projet.')
    await click(document.body.querySelector('[data-testid="badge-switch"] button[role="switch"], button[data-testid="badge-switch"]')!)
    expect(callsTo('PUT', `/api/badges/projects/${PROJECT}`)[0]!.body).toEqual({ enabled: true })
    expect(document.body.querySelector('img[src="/api/badges/alpha.svg"]')).not.toBeNull()
  })

  it('lecteur : ni jetons ni bascule du badge', async () => {
    setUser('viewer')
    route('GET', `/api/gates/projects/${PROJECT}`, () => info())
    await mount(CiPage, { route: `/gates/projects/${PROJECT}` })
    expect(document.body.querySelector('[data-testid="token-create"]')).toBeNull()
    expect(callsTo('GET', `/api/projects/${PROJECT}/tokens`)).toHaveLength(0)
  })
})

describe('VerdictPanel', () => {
  const details = (verdict: VerdictDetails['verdict'], reasons: VerdictDetails['reasons'] = []): VerdictDetails => ({
    verdict, gate_id: GATE, rules: RULES, evaluated_at: '2026-11-24T10:00:00Z', new_code_only: true,
    counts: { critical: 1, high: 2, medium: 0, low: 0, info: 0 }, reasons,
    exceptions_applied: [{ id: TOKEN, reason: 'jeux d’essai', expires_on: '2026-12-31' }],
  })

  it('verdict, raisons ordonnées, actions et exceptions', async () => {
    await mount(VerdictPanel, {
      props: {
        scanId: OTHER,
        projectId: PROJECT,
        details: details('failed', [
          { code: 'secret', blocking: true, count: 2, severity: 'high', module: null, finding_ids: [TOKEN], actions: ['fix', 'request-exception'] },
          { code: 'module-missing', blocking: true, count: 1, severity: null, module: 'trivy', finding_ids: [], actions: ['install-module'] },
          { code: 'coverage-gap', blocking: false, count: 3, severity: null, module: null, finding_ids: [], actions: [] },
        ]),
      },
    })
    const text = bodyText()
    expect(text).toContain('Échec')
    expect(text).toContain('Ce qui bloque, dans l’ordre')
    const reasons = Array.from(document.body.querySelectorAll('[data-testid="verdict-reason"]')).map(e => e.textContent)
    expect(reasons[0]).toContain('Secrets ×2')
    expect(reasons[1]).toContain('Module absent')
    expect(reasons[1]).toContain('trivy')
    expect(text).toContain('Trous de couverture ×3')
    expect(text).toContain('jeux d’essai')
    const links = Array.from(document.body.querySelectorAll('a')).map(a => a.getAttribute('href'))
    expect(links).toContain(`/findings?scan=${OTHER}&ids=${TOKEN}`)
    expect(links).toContain('/catalog')
  })

  it('en attente, texte IA en prop ou dans le slot « ai »', async () => {
    await mount(VerdictPanel, { props: { details: null } })
    expect(bodyText()).toContain('Verdict en attente')
    clearBody()
    await mount(VerdictPanel, { props: { details: details('passed'), aiSummary: { summary: 'Tout va bien.', model: 'm1' } } })
    expect(bodyText()).toContain('Proposé par IA (m1)')
    expect(bodyText()).toContain('Tout va bien.')
    clearBody()
    await setLocale('en')
    await mount(VerdictPanel, { props: { details: details('inconclusive') }, slots: { ai: () => h('p', 'texte de F') } })
    expect(bodyText()).toContain('Inconclusive')
    expect(document.body.querySelector('[data-testid="verdict-ai"]')!.textContent).toContain('texte de F')
  })
})
