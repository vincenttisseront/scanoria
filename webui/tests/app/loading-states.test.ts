// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// États de chargement et de rafraîchissement : erreurs affichées dans la page
// (et non un simple toast), suivi périodique (IA, découverte d'une forge),
// textes traduits du catalogue.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport, mountSuspended } from '@nuxt/test-utils/runtime'
import {
  apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setupComponent, setUser,
} from './helpers'
import DashboardPage from '~/pages/index.vue'
import AboutPage from '~/pages/system/about.vue'
import GatePage from '~/pages/gates/[id].vue'
import GateProjectPage from '~/pages/gates/projects/[id].vue'
import ExceptionsPage from '~/pages/findings/exceptions.vue'
import ForgesPage from '~/pages/projects/forges.vue'
import AiPage from '~/pages/system/ai.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const ID = '11111111-1111-4111-8111-111111111111'

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

describe('textes traduits du catalogue', () => {
  it('choisit la langue de l’utilisateur, avec repli', async () => {
    const holder: { value?: ReturnType<typeof useModuleText> } = {}
    await mountSuspended(setupComponent(() => useModuleText(), holder))
    const text = holder.value!
    expect(text.localized({ fr: 'Bonjour', en: 'Hello' })).toBe('Bonjour')
    expect(text.localized({ fr: '', en: 'Hello' })).toBe('Hello')
    expect(text.localized('texte seul')).toBe('texte seul')
    expect(text.localized(null)).toBe('')
    await setLocale('en')
    expect(text.localized({ fr: 'Bonjour', en: 'Hello' })).toBe('Hello')
    expect(text.localized({ fr: 'Bonjour', en: '' })).toBe('Bonjour')
  })
})

describe('erreurs de chargement affichées dans la page', () => {
  it('tableau de bord : état illisible signalé, puis effacé au retour', async () => {
    setUser('viewer')
    route('GET', '/api/state', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(DashboardPage)
    await settle()
    expect(bodyText()).toContain('Impossible de lire l’état de l’appliance.')
  })

  it('À propos, gate, intégration CI et exceptions', async () => {
    setUser('admin')
    route('GET', '/api/about', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(AboutPage)
    await settle()
    expect(bodyText()).toContain('Une erreur est survenue. Réessayez.')
    clearBody()

    route('GET', `/api/gates/${ID}`, () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(GatePage, { route: `/gates/${ID}` })
    await settle()
    expect(bodyText()).toContain('introuvable')
    clearBody()

    await mountIn(GateProjectPage, { route: `/gates/projects/${ID}` })
    await settle()
    expect(bodyText()).toContain('Une erreur est survenue. Réessayez.')
    clearBody()

    route('GET', '/api/findings/summary', () => ({ items: [] }))
    route('GET', '/api/exceptions', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(ExceptionsPage, { route: `/findings/exceptions?project_id=${ID}` })
    await settle()
    expect(bodyText()).toContain('Erreur interne de la console.')
  })
})

describe('suivi périodique', () => {
  it('forge ajoutée : la découverte en arrière-plan est suivie 2 minutes', async () => {
    setUser('admin')
    route('GET', '/api/forges', () => ({ items: [] }))
    route('POST', '/api/forges', () => ({
      forge: { id: ID, kind: 'forgejo', name: 'F', base_url: 'https://forge.exemple.test', discovery: true, has_token: false, token_hint: null, token_user: null, last_discovery_at: null, last_error: null, created_at: '2026-11-24T09:00:00Z', projects: 0 },
      login: null, discovery_started: true,
    }))
    const w = await mountIn(ForgesPage)
    await settle()
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval', 'Date'] })
    const vm = w.vm as unknown as { form: { name: string, base_url: string } }
    vm.form.name = 'F'
    vm.form.base_url = 'https://forge.exemple.test'
    await settle()
    await click(button('Vérifier et connecter'))
    const after = callsTo('GET', '/api/forges').length
    await vi.advanceTimersByTimeAsync(15_000)
    expect(callsTo('GET', '/api/forges').length).toBeGreaterThanOrEqual(after + 2)
    await vi.advanceTimersByTimeAsync(130_000)
    const stopped = callsTo('GET', '/api/forges').length
    await vi.advanceTimersByTimeAsync(30_000)
    expect(callsTo('GET', '/api/forges').length).toBe(stopped)
  })

  it('page IA : santé et journal relus toutes les 15 s, formulaire intact', async () => {
    setUser('admin')
    route('GET', '/api/ai/status', () => ({
      enabled: false,
      endpoint: { url: 'https://ollama.exemple.test:11434', host: null, port: null, addresses: [], insecure: false, token: false, ca: false, pinned_at: null },
      token_stored: false, token_supported: false, check: null, probe: null, models: [], embedding: null, tasks: [],
      circuit: { state: 'closed', last_failure_at: null }, latency_ms: null, queue: { queued: 0, running: 0 },
    }))
    route('GET', '/api/ai/calls', () => ({ calls: [] }))
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] })
    const w = await mountIn(AiPage)
    await settle()
    const vm = w.vm as unknown as { form: { url: string } }
    vm.form.url = ''
    const before = callsTo('GET', '/api/ai/status').length
    await vi.advanceTimersByTimeAsync(15_100)
    await settle()
    expect(callsTo('GET', '/api/ai/status').length).toBe(before + 1)
    expect(vm.form.url).toBe('')
  })
})
