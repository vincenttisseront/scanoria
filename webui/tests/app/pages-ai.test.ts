// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Système › Intelligence artificielle et explications proposées par IA
// (CLAUDE.md § 3.5, I1, I2, I9) : une seule saisie, serveur candidat, modale
// d'activation avec case à cocher, indicateurs d'attente, modèles par tâche et
// pourquoi, lecture seule pour un opérateur ; composant d'explication masqué
// sans connecteur, sondage pendant la rédaction, texte affiché brut.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import {
  bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser,
} from './helpers'
import AiPage from '~/pages/system/ai.vue'
import AiExplanation from '~/components/AiExplanation.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)

const FINDING = '11111111-1111-4111-8111-111111111111'
const SCAN = '22222222-2222-4222-8222-222222222222'
const DIGEST = 'c'.repeat(64)
const URL_INPUT = 'input[data-testid="ai-url"], [data-testid="ai-url"] input'

function aiStatus(patch: Record<string, unknown> = {}) {
  return {
    enabled: false,
    endpoint: { url: null, host: null, port: null, addresses: [], insecure: false, token: false, ca: false, pinned_at: null },
    token_stored: false,
    token_supported: false,
    check: null,
    probe: null,
    models: [],
    embedding: null,
    tasks: [
      { kind: 'explain-finding', model: null, override: null, testbed: null, threshold: 0.75, state: 'off' },
      { kind: 'explain-verdict', model: null, override: null, testbed: null, threshold: 0.75, state: 'off' },
    ],
    circuit: { state: 'closed', last_failure_at: null },
    latency_ms: null,
    queue: { queued: 0, running: 0 },
    ...patch,
  }
}

function activeStatus(patch: Record<string, unknown> = {}) {
  const choice = { model: 'qwen-test:14b', digest: DIGEST, reason: 'best-balance' }
  return aiStatus({
    enabled: true,
    endpoint: { url: 'https://ollama.exemple.test:11434', host: 'ollama.exemple.test', port: 11434, addresses: ['192.0.2.10'], insecure: false, token: true, ca: true, pinned_at: '2026-11-24T09:00:00Z' },
    probe: { status: 'done', error: null, at: '2026-11-24T09:05:00Z', version: '0.12.3' },
    models: [
      { name: 'qwen-test:14b', capabilities: ['completion'] },
      { name: 'small-test:3b', capabilities: ['completion'] },
      { name: 'embed-test:latest', capabilities: ['embedding'] },
    ],
    embedding: { model: 'embed-test:latest', reason: 'only-model' },
    tasks: [
      { kind: 'explain-finding', model: choice, override: null, testbed: { score: 1, threshold: 0.75, passed: true, at: '2026-11-24T09:06:00Z' }, threshold: 0.75, state: 'active' },
      { kind: 'explain-verdict', model: { ...choice, reason: 'admin-choice' }, override: 'qwen-test:14b', testbed: { score: 0.5, threshold: 0.75, passed: false, at: '2026-11-24T09:06:00Z' }, threshold: 0.75, state: 'disabled' },
    ],
    latency_ms: 420,
    queue: { queued: 2, running: 1 },
    ...patch,
  })
}

const CALLS = [
  { id: 2, kind: 'explain-finding', model: 'qwen-test:14b', bytes_sent: 1834, duration_ms: 950, outcome: 'ok', at: '2026-11-24T09:10:00Z', project: 'alpha' },
  { id: 1, kind: 'probe', model: null, bytes_sent: 0, duration_ms: null, outcome: 'timeout', at: '2026-11-24T09:00:00Z', project: null },
]

/** Demande au service root : dépôt puis résultat final au premier suivi. */
function helperRoute(path: string, id: string) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'set-ai-endpoint', step: null, message: null, output: null, status: 'ok', code: 'OK' }))
}

async function drive(rounds = 3): Promise<void> {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(2100)
  await settle()
}

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

describe('page Système › IA', () => {
  it('administrateur sans connecteur : candidat proposé, http à autoriser, modale d’activation lue puis demande', async () => {
    setUser('admin')
    let enabled = false
    route('GET', '/api/ai/status', () => (enabled
      ? activeStatus()
      : aiStatus({ check: { checked_at: '2026-11-24T09:00:00Z', resolution: null, candidate: { url: 'http://ollama.exemple.test:11434', version: '0.12.3', addresses: ['192.0.2.10'], insecure: true } } })))
    route('GET', '/api/ai/calls', () => ({ calls: [] }))
    helperRoute('/api/ai/connector', 'c1')
    const w = await mountIn(AiPage)
    await settle()
    expect(w.text()).toContain('Inactif')
    expect(w.text()).toContain('Aucun appel pour l’instant.')
    expect(w.text()).not.toContain('Modèles par tâche')
    expect(w.text()).toContain('Serveur détecté automatiquement : http://ollama.exemple.test:11434 (Ollama 0.12.3).')
    expect(w.text()).toContain('Le jeton porteur sera disponible')
    expect(button('Activer le connecteur').disabled).toBe(true)

    await w.find(URL_INPUT).setValue('https://ollama.exemple.test:11434/api')
    expect(button('Activer le connecteur').disabled).toBe(true)
    await w.find(URL_INPUT).setValue('http://192.0.2.10:11434')
    expect(w.text()).toContain('circulent en clair')
    expect(button('Activer le connecteur').disabled).toBe(true)

    await click(button('Utiliser ce serveur'))
    expect((w.find(URL_INPUT).element as HTMLInputElement).value).toBe('http://ollama.exemple.test:11434')
    expect(button('Activer le connecteur').disabled).toBe(false)

    // Horloge simulée après le premier montage (le premier montage de Nuxt a besoin des vraies minuteries).
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    await click(button('Activer le connecteur'))
    const dialog = bodyText()
    expect(dialog).toContain('Des extraits de données vont quitter l’appliance vers http://ollama.exemple.test:11434.')
    expect(dialog).toContain('Ce qui n’est jamais envoyé')
    expect(dialog).toContain('la valeur d’un secret trouvé')
    expect(dialog).toContain('aucun envoi à l’IA')
    expect(button('Activer').disabled).toBe(true)
    await click(document.body.querySelector('[role="dialog"] [role="checkbox"]')!)
    enabled = true
    button('Activer').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/ai/connector')[0]!.body).toEqual({ url: 'http://ollama.exemple.test:11434', allow_insecure: true, confirmed: true })
    expect(document.body.querySelector('[role="dialog"]')).toBeNull()
    expect(w.text()).toContain('Actif')
    expect(w.text()).toContain('192.0.2.10')
  })

  it('connecteur actif : modèles et pourquoi, banc d’essai, santé, journal, choix d’un modèle', async () => {
    setUser('admin')
    route('GET', '/api/ai/status', () => activeStatus({ circuit: { state: 'open', last_failure_at: '2026-11-24T09:00:00Z' } }))
    route('GET', '/api/ai/calls', () => ({ calls: CALLS }))
    route('GET', '/api/ai/agreement', () => ({ days: 90, items: [
      { kind: 'explain-finding', model: 'qwen-test:14b', votes: 4, up: 3, rate: 0.75, triaged: null, matched: null, triage_rate: null },
      { kind: 'triage-finding', model: 'qwen-test:14b', votes: 0, up: 0, rate: null, triaged: 5, matched: 4, triage_rate: 0.8 },
    ] }))
    route('PUT', '/api/ai/models', () => ({ models: {} }))
    route('POST', '/api/ai/probe', () => ({ queued: true }))
    const w = await mountIn(AiPage)
    await settle()
    const text = w.text()
    expect(text).toContain('Actif')
    expect(text).toContain('jeton porteur, AC personnalisée')
    const finding = w.find('[data-testid="ai-task-explain-finding"]').text()
    expect(finding).toContain('Explication d’un résultat')
    expect(finding).toContain('qwen-test:14b')
    expect(finding).toContain('meilleur équilibre taille, contexte et rapidité')
    expect(finding).toContain('100 % (seuil 75 %)')
    expect(finding).toContain('active')
    const verdict = w.find('[data-testid="ai-task-explain-verdict"]').text()
    expect(verdict).toContain('choisi par un administrateur')
    expect(verdict).toContain('désactivée par le banc d’essai')
    expect(text).toContain('embed-test:latest (seul modèle disponible)')
    expect(text).toContain('0.12.3')
    expect(text).toContain('420 ms')
    expect(text).toContain('ouvert : serveur injoignable')
    expect(text).toContain('2 en attente, 1 en cours')
    expect(text).toContain('alpha')
    expect(text).toContain('1834')
    expect(text).toContain('délai dépassé')
    // I24 : taux d'accord par tâche et par modèle.
    const agreement = w.find('[data-testid="ai-agreement"]').text()
    expect(agreement).toContain('Qualité mesurée')
    expect(agreement).toContain('75 %')
    expect(agreement).toContain('80 % (4 sur 5)')

    await click(button('Redécouvrir les modèles'))
    expect(callsTo('POST', '/api/ai/probe')).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success' }))

    // Choix d'un modèle : appel direct du gestionnaire de la liste (rendu de USelect hors périmètre).
    const vm = w.vm as unknown as { setOverride: (k: string, v: string) => Promise<void> }
    await vm.setOverride('explain-verdict', '__auto__')
    await vm.setOverride('explain-finding', 'small-test:3b')
    expect(callsTo('PUT', '/api/ai/models').map(c => c.body)).toEqual([
      { models: { 'explain-verdict': null } },
      { models: { 'explain-finding': 'small-test:3b' } },
    ])
  })

  it('résolution changée : avertissement, nouvelle confirmation proposée ; retrait par modale', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('admin')
    route('GET', '/api/ai/status', () => activeStatus({
      check: { checked_at: '2026-11-24T10:00:00Z', resolution: { pinned: ['192.0.2.10'], current: ['192.0.2.11'], changed: true, error: null }, candidate: null },
    }))
    route('GET', '/api/ai/calls', () => ({ calls: [] }))
    helperRoute('/api/ai/disconnect', 'd1')
    const w = await mountIn(AiPage)
    await settle()
    expect(w.text()).toContain('résout maintenant vers d’autres adresses (192.0.2.11)')
    await click(button('Confirmer à nouveau'))
    expect(bodyText()).toContain('Activer le connecteur IA')
    await click(button('Annuler'))

    await click(button('Retirer le connecteur'))
    expect(bodyText()).toContain('La sortie réseau de scanoria-ai sera refermée.')
    button('Retirer le connecteur').dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await drive()
    expect(callsTo('POST', '/api/ai/disconnect')[0]!.body).toEqual({})
  })

  it('opérateur : lecture seule ; erreur de lecture signalée', async () => {
    setUser('operator')
    route('GET', '/api/ai/status', () => activeStatus({
      check: { checked_at: '2026-11-24T10:00:00Z', resolution: { pinned: ['192.0.2.10'], current: [], changed: false, error: 'E_AI_UNRESOLVED' }, candidate: null },
    }))
    route('GET', '/api/ai/calls', () => ({ calls: CALLS }))
    const w = await mountIn(AiPage)
    await settle()
    expect(w.text()).toContain('Le dernier contrôle du nom du serveur a échoué (E_AI_UNRESOLVED).')
    expect(w.find('[data-testid="ai-url"]').exists()).toBe(false)
    expect(buttons('Retirer le connecteur')).toHaveLength(0)
    expect(buttons('Redécouvrir les modèles')).toHaveLength(0)
    expect(w.text()).not.toContain('Choix')

    resetApi()
    const w2 = await mountIn(AiPage)
    await settle()
    expect(w2.text()).not.toContain('Connecteur Ollama')
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })
})

describe('explication proposée par IA', () => {
  it('sans connecteur et sans sortie : rien n’est affiché', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', () => ({ enabled: false, opt_out: false, task: null }))
    const w = await mountIn(AiExplanation, { props: { kind: 'explain-finding', subjectId: FINDING } })
    await settle()
    expect(w.find('[data-testid="ai-explanation"]').exists()).toBe(false)
  })

  it('demande, attente avec indicateur, puis texte brut avec mention IA et références sûres', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'] })
    setUser('viewer')
    let state: 'none' | 'queued' | 'done' = 'none'
    route('GET', '/api/ai/output', () => ({
      enabled: true,
      opt_out: false,
      task: state === 'none'
        ? null
        : state === 'queued'
          ? { id: 't1', status: 'queued', locale: 'fr', error: null, output: null, model: null, model_digest: null, generated_at: null }
          : {
              id: 't1', status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: DIGEST, generated_at: '2026-11-24T09:00:00Z',
              output: {
                summary: '<b>Injection SQL</b> dans app/db.py.',
                detects: 'Requête construite par concaténation.',
                risk: 'Entrée utilisateur non filtrée.',
                impact: 'Lecture de la base.',
                fix: 'Utiliser des requêtes paramétrées.',
                references: [
                  { label: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
                  { label: 'Piège', url: 'javascript:void(0)' },
                  { label: 'Ailleurs', url: 'https://evil.exemple.test/' },
                ],
              },
            },
    }))
    route('POST', '/api/ai/explain', () => {
      state = 'queued'
      return { task_id: 't1' }
    })
    const w = await mountIn(AiExplanation, { props: { kind: 'explain-finding', subjectId: FINDING } })
    await settle()
    await click(button('Expliquer avec l’IA'))
    expect(callsTo('POST', '/api/ai/explain')[0]!.body).toEqual({ kind: 'explain-finding', subject_id: FINDING, locale: 'fr' })
    expect(w.find('[data-testid="ai-pending"]').text()).toContain('L’IA rédige l’explication…')
    state = 'done'
    await vi.advanceTimersByTimeAsync(3100)
    await settle()
    const text = w.text()
    expect(text).toContain('<b>Injection SQL</b> dans app/db.py.')
    expect(w.find('b').exists()).toBe(false)
    expect(text).toContain(`proposé par IA · qwen-test:14b (${'c'.repeat(12)})`)
    expect(text).toContain('Ce que la règle détecte')
    expect(text).toContain('Utiliser des requêtes paramétrées.')
    const links = w.findAll('a').map(a => a.attributes('href'))
    expect(links).toEqual(['https://cwe.mitre.org/data/definitions/89.html'])
    expect(w.find('a').attributes('rel')).toContain('noopener')
  })

  it('verdict expliqué : cause et actions ordonnées', async () => {
    setUser('viewer')
    await setLocale('en')
    route('GET', '/api/ai/output', () => ({
      enabled: true, opt_out: false,
      task: { id: 't2', status: 'done', locale: 'en', error: null, model: 'qwen-test:14b', model_digest: null, generated_at: null, output: { summary: 'Blocked by a secret.', blocking: 'secret (gitleaks)', actions: ['Revoke the secret', 'Request an exception'] } },
    }))
    const w = await mountIn(AiExplanation, { props: { kind: 'explain-verdict', subjectId: SCAN } })
    await settle()
    expect(w.text()).toContain('Verdict explained')
    expect(w.text()).toContain('suggested by AI · qwen-test:14b')
    expect(w.text()).toContain('Main cause')
    expect(w.findAll('li').map(l => l.text())).toEqual(['Revoke the secret', 'Request an exception'])
  })

  it('projet exclu, erreur avec nouvel essai, sortie illisible', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', () => ({ enabled: true, opt_out: true, task: null }))
    const w = await mountIn(AiExplanation, { props: { kind: 'explain-finding', subjectId: FINDING } })
    await settle()
    expect(w.text()).toContain('aucun envoi à l’IA')
    expect(buttons('Expliquer avec l’IA')).toHaveLength(0)
    resetApi()

    route('GET', '/api/ai/output', () => ({
      enabled: true, opt_out: false,
      task: { id: 't3', status: 'error', locale: 'fr', error: 'timeout', output: null, model: null, model_digest: null, generated_at: null },
    }))
    route('POST', '/api/ai/explain', () => ({ task_id: null }))
    const w2 = await mountIn(AiExplanation, { props: { kind: 'explain-finding', subjectId: FINDING } })
    await settle()
    expect(w2.text()).toContain('Explication indisponible (délai dépassé).')
    await click(button('Réessayer'))
    expect(callsTo('POST', '/api/ai/explain')).toHaveLength(1)
    resetApi()

    const w3 = await mountIn(AiExplanation, { props: { kind: 'explain-finding', subjectId: FINDING } })
    await settle()
    expect(w3.find('[data-testid="ai-explanation"]').exists()).toBe(false)
  })
})
