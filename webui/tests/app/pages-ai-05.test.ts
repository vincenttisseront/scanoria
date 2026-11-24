// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sorties IA de la 0.5 dans la console (CLAUDE.md § 3.5) : résultats
// semblables (I7) et tri commun appliqué un par un après une modale,
// atteignabilité (I11) qui ne touche à rien, licence expliquée (I18) avec la
// mention « pas un avis juridique ». Sans connecteur, rien n'est affiché.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, calls, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import AiSimilarFindings from '~/components/ai/SimilarFindings.vue'
import AiReachability from '~/components/ai/Reachability.vue'
import AiLicenseExplanation from '~/components/ai/LicenseExplanation.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  resetApi()
  clearBody()
})

const P1 = '11111111-1111-4111-8111-111111111111'
const F1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const F2 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const F3 = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const DIGEST = 'd'.repeat(64)

function done(id: string, output: Record<string, unknown>) {
  return { enabled: true, opt_out: false, task: { id, status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: DIGEST, generated_at: '2026-11-24T09:00:00Z', output, feedback: null } }
}
const item = (id: string, title: string, score: number) => ({ id, score, title, tool: 'semgrep', rule_id: 'python.sqli', severity: 'high', status: 'new', path: 'app/a.py', start_line: 3 })
const ready = (items: ReturnType<typeof item>[]) => ({ enabled: true, state: 'ready', model: 'embed-test:latest', model_digest: 'b'.repeat(64), threshold: 0.75, items })

describe('résultats semblables (I7)', () => {
  it('opérateur : sélection, modale, un appel de tri par résultat, page rafraîchie', async () => {
    setUser('operator')
    route('GET', '/api/ai/similar', () => ready([item(F2, 'SQL injection B', 0.91), item(F3, 'SQL injection C', 0.82)]))
    route('POST', `/api/findings/${F2}/status`, () => ({ ok: true }))
    route('POST', `/api/findings/${F3}/status`, () => ({ ok: true }))
    const w = await mountIn(AiSimilarFindings, { props: { findingId: F1 } })
    await settle()
    expect(callsTo('GET', '/api/ai/similar')[0]!.query).toEqual({ finding_id: F1 })
    expect(w.text()).toContain('Résultats semblables')
    expect(w.text()).toContain('91 % semblable')
    expect(w.text()).toContain('le quality gate n’en tient pas compte')
    expect(bodyText()).toContain('proposé par IA · embed-test:latest')

    for (const cb of w.findAll('[role="checkbox"]')) await cb.trigger('click')
    await settle()
    await click(document.body.querySelector('[data-testid="ai-similar-triage"]')!)
    expect(bodyText()).toContain('Appliquer le même tri à 2 résultats ?')
    // Rien n'est envoyé avant la confirmation.
    expect(calls.filter(c => c.path.includes('/status'))).toHaveLength(0)
    await click(button('Appliquer'))
    expect(callsTo('POST', `/api/findings/${F2}/status`)[0]!.body).toEqual({ status: 'confirmed' })
    expect(callsTo('POST', `/api/findings/${F3}/status`)[0]!.body).toEqual({ status: 'confirmed' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success', title: '2 résultat(s) trié(s) sur 2.' }))
    expect(w.emitted('triaged')).toHaveLength(1)
  })

  it('faux positif sans motif refusé avant tout appel ; un semblable s\'ouvre dans le panneau', async () => {
    setUser('operator')
    route('GET', '/api/ai/similar', () => ready([item(F2, 'SQL injection B', 0.9)]))
    const w = await mountIn(AiSimilarFindings, { props: { findingId: F1 } })
    await settle()
    await w.find('[role="checkbox"]').trigger('click')
    await settle()
    await click(document.body.querySelector('[data-testid="ai-similar-triage"]')!)
    // Choix « faux positif » dans le formulaire de la modale, sans motif.
    const state = (w.vm as unknown as { $: { setupState: { form: { status: string } } } }).$.setupState
    state.form.status = 'false-positive'
    await settle()
    await click(button('Appliquer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
    expect(calls.filter(c => c.path.includes('/status'))).toHaveLength(0)
    await w.find('button.text-left').trigger('click')
    expect(w.emitted('open')).toEqual([[F2]])
  })

  it('lecteur : liste sans case ni tri ; modèle d\'embedding absent signalé ; rien sans connecteur', async () => {
    setUser('viewer')
    route('GET', '/api/ai/similar', () => ready([item(F2, 'SQL injection B', 0.9)]))
    const w = await mountIn(AiSimilarFindings, { props: { findingId: F1 } })
    await settle()
    expect(w.text()).toContain('SQL injection B')
    expect(w.findAll('[role="checkbox"]')).toHaveLength(0)
    resetApi()
    clearBody()

    route('GET', '/api/ai/similar', () => ({ enabled: true, state: 'no-embedding-model', model: null, model_digest: null, threshold: null, items: [] }))
    const w2 = await mountIn(AiSimilarFindings, { props: { findingId: F1 } })
    await settle()
    expect(w2.text()).toContain('le serveur IA n’a pas de modèle d’embedding')
    resetApi()
    clearBody()

    for (const state of ['off', 'opt-out']) {
      route('GET', '/api/ai/similar', () => ({ enabled: state !== 'off', state, model: null, model_digest: null, threshold: null, items: [] }))
      const w3 = await mountIn(AiSimilarFindings, { props: { findingId: F1 } })
      await settle()
      expect(w3.find('[data-testid="ai-similar"]').exists()).toBe(false)
      resetApi()
      clearBody()
    }
  })

  it('recherche en cours : indicateur d\'attente', async () => {
    setUser('viewer')
    route('GET', '/api/ai/similar', () => ({ enabled: true, state: 'pending', model: 'embed-test:latest', model_digest: null, threshold: 0.75, items: [] }))
    const w = await mountIn(AiSimilarFindings, { props: { findingId: F1, pollMs: 60_000 } })
    await settle()
    expect(w.find('[data-testid="ai-pending"]').exists()).toBe(true)
    expect(w.text()).toContain('Recherche des résultats semblables…')
  })
})

describe('atteignabilité (I11)', () => {
  it('avis, emplacements cités, sortie échappée ; aucun appel qui change un statut', async () => {
    setUser('operator')
    route('GET', '/api/ai/output', () => done('t-reach', {
      reachability: 'probable', summary: 'Appel de <b>minimist</b> dans src/cli.js.', downgraded: false,
      reasons: [{ ref: 1, explanation: 'Appel direct.' }],
      cited: [{ ref: 1, kind: 'call', path: 'src/cli.js', line: 4, symbol: 'minimist' }],
    }))
    const w = await mountIn(AiReachability, { props: { findingId: F1 } })
    await settle()
    expect(w.find('[data-testid="ai-reach-verdict"]').text()).toBe('Appel probable')
    expect(w.text()).toContain('src/cli.js:4 · appel minimist')
    expect(w.text()).toContain('Appel de <b>minimist</b>')
    expect(w.find('[data-testid="ai-reachability"] b').exists()).toBe(false)
    expect(w.text()).toContain('ne lève jamais un blocage')
    expect(calls.filter(c => c.method !== 'GET' && !c.path.startsWith('/api/ai/'))).toHaveLength(0)
  })

  it('avis ramené à « indéterminé » expliqué ; rien sans connecteur ni avis', async () => {
    setUser('viewer')
    route('GET', '/api/ai/output', () => done('t-reach', { reachability: 'indeterminate', summary: 'Pas assez d’éléments.', reasons: [], cited: [], downgraded: true }))
    const w = await mountIn(AiReachability, { props: { findingId: F1 } })
    await settle()
    expect(w.text()).toContain('Indéterminé')
    expect(w.text()).toContain('Avis ramené à « indéterminé »')
    resetApi()
    clearBody()
    route('GET', '/api/ai/output', () => ({ enabled: false, opt_out: false, task: null }))
    const w2 = await mountIn(AiReachability, { props: { findingId: F1 } })
    await settle()
    expect(w2.find('[data-testid="ai-reachability"]').exists()).toBe(false)
  })
})

describe('licence expliquée (I18)', () => {
  it('clé demandée au serveur, explication marquée IA et « pas un avis juridique »', async () => {
    setUser('viewer')
    route('GET', '/api/ai/license-key', () => ({ found: true, key: 'GPL-3.0-only|MIT' }))
    route('GET', '/api/ai/output', () => done('t-lic', {
      summary: 'Copyleft fort.', obligations: ['Fournir le code source'], compatibility: 'incompatible',
      compatibility_note: 'Le code MIT combiné devient GPL.', to_check: ['Mode de distribution'],
    }))
    const w = await mountIn(AiLicenseExplanation, { props: { license: 'GPL-3.0-only', projectId: P1 } })
    await settle()
    expect(callsTo('GET', '/api/ai/license-key')[0]!.query).toEqual({ license: 'GPL-3.0-only', project_id: P1 })
    expect(callsTo('GET', '/api/ai/output')[0]!.query).toMatchObject({ kind: 'explain-license', subject_id: 'GPL-3.0-only|MIT' })
    expect(w.text()).toContain('Incompatible avec la licence du projet')
    expect(w.text()).toContain('Fournir le code source')
    expect(w.find('[data-testid="ai-license-not-legal"]').text()).toContain('pas un avis juridique')
    expect(bodyText()).toContain('proposé par IA')
  })

  it('projet exclu ou sans connecteur : rien n\'est demandé ni affiché', async () => {
    setUser('viewer')
    route('GET', '/api/ai/license-key', () => ({ found: true, key: null }))
    const w = await mountIn(AiLicenseExplanation, { props: { license: 'GPL-3.0-only', projectId: P1 } })
    await settle()
    expect(callsTo('GET', '/api/ai/output')).toHaveLength(0)
    expect(w.find('[data-testid="ai-license"]').exists()).toBe(false)
  })
})
