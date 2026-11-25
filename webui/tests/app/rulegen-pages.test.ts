// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Générateur de règles (I12) dans la console : masqué sans connecteur ou pour
// un lecteur, règle et exemples affichés comme texte, test lancé aussitôt,
// enregistrement réservé aux administrateurs, après une modale de la console
// avec case de relecture, et seulement si le test passe.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import AiRuleGenerator from '~/components/ai/RuleGenerator.vue'

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

const F1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const RS = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const SUBJECT = `rg:${'c'.repeat(64)}`
const OUTPUT = {
  rule_id: 'no-eval',
  rule: 'rules:\n  - id: no-eval\n    message: eval <script>\n    pattern: eval(...)\n',
  positive: { filename: 'bad.py', content: 'eval(input())' },
  negative: { filename: 'good.py', content: 'print(input())' },
  explanation: 'Détecte eval() sur une donnée.',
}

function routes(opts: { available?: boolean, passed?: boolean } = {}) {
  const available = opts.available ?? true
  route('GET', '/api/ai/rules', e => (new URL(e.node.req.url!, 'http://x').searchParams.get('subject_id')
    ? { enabled: true, available, engine: 'opengrep', task: { id: 't1', status: 'done', error: null, output: OUTPUT, model: 'qwen-test:14b', model_digest: 'd'.repeat(64) } }
    : { enabled: true, available, engine: null, task: null }))
  route('POST', '/api/ai/rules', () => ({ subject_id: SUBJECT, task_id: 't1' }))
  route('POST', '/api/ai/rules/test', () => ({ passed: opts.passed ?? true, positive_matches: opts.passed === false ? 0 : 1, negative_matches: 0, errors: opts.passed === false ? ['pattern never matches'] : [], engine: 'opengrep' }))
  route('GET', '/api/ai/rules/rulesets', () => ({ items: [{ id: RS, slug: 'maison', name: 'Règles maison', latest_version: 3 }] }))
  route('POST', '/api/ai/rules/save', () => ({ version: 4 }))
}

describe('générateur de règles (I12)', () => {
  it('masqué sans connecteur et pour un lecteur', async () => {
    setUser('operator')
    route('GET', '/api/ai/rules', () => ({ enabled: false, available: false, engine: null, task: null }))
    const w = await mountIn(AiRuleGenerator, { props: { findingId: F1 } })
    await settle()
    expect(w.find('[data-testid="ai-rulegen"]').exists()).toBe(false)
    resetApi()
    setUser('viewer')
    routes()
    const v = await mountIn(AiRuleGenerator, { props: { findingId: F1 } })
    await settle()
    expect(v.find('[data-testid="ai-rulegen"]').exists()).toBe(false)
  })

  it('opérateur : proposition depuis le résultat, test aussitôt, aucun enregistrement possible', async () => {
    setUser('operator')
    routes()
    const w = await mountIn(AiRuleGenerator, { props: { findingId: F1 } })
    await settle()
    await w.find('form').trigger('submit')
    await settle()
    expect(callsTo('POST', '/api/ai/rules')[0]!.body).toEqual({ engine: 'opengrep', source: 'finding', locale: 'fr', finding_id: F1 })
    expect(callsTo('POST', '/api/ai/rules/test')[0]!.body).toEqual({ subject_id: SUBJECT })
    expect(bodyText()).toContain('no-eval')
    // Texte brut : le chevron reste du texte, jamais une balise.
    expect(document.body.querySelector('[data-testid="ai-rulegen-result"] script')).toBeNull()
    expect(bodyText()).toContain('message: eval <script>')
    expect(bodyText()).toContain('Test réussi')
    expect(bodyText()).toContain('proposé par IA · qwen-test:14b')
    expect(w.find('[data-testid="ai-rulegen-save"]').exists()).toBe(false)
  })

  it('administrateur : modale avec case de relecture, enregistrement dans un jeu existant', async () => {
    setUser('admin')
    routes()
    const w = await mountIn(AiRuleGenerator, { props: { defaultEngine: 'opengrep' } })
    await settle()
    await w.find('textarea').setValue('Interdire eval()')
    await w.find('form').trigger('submit')
    await settle()
    expect(callsTo('POST', '/api/ai/rules')[0]!.body).toMatchObject({ source: 'phrase', description: 'Interdire eval()' })
    await click(document.body.querySelector('[data-testid="ai-rulegen-save"]')!)
    expect(callsTo('GET', '/api/ai/rules/rulesets')[0]!.query).toEqual({ engine: 'opengrep' })
    expect(bodyText()).toContain('Enregistrer la règle proposée par IA')
    const confirm = button('Enregistrer la règle')
    expect(confirm.disabled).toBe(true)
    expect(callsTo('POST', '/api/ai/rules/save')).toHaveLength(0)
    const state = (w.vm as unknown as { $: { setupState: { save: { target: string } } } }).$.setupState
    state.save.target = RS
    await click(document.body.querySelector('[role="checkbox"]')!)
    await click(button('Enregistrer la règle'))
    expect(callsTo('POST', '/api/ai/rules/save')[0]!.body).toEqual({ subject_id: SUBJECT, confirmed: true, ruleset_id: RS })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success', title: 'Règle enregistrée (version 4).' }))
  })

  it('test échoué : erreurs affichées, aucun bouton d’enregistrement', async () => {
    setUser('admin')
    routes({ passed: false })
    const w = await mountIn(AiRuleGenerator, { props: { findingId: F1 } })
    await settle()
    await w.find('form').trigger('submit')
    await settle()
    expect(bodyText()).toContain('Test échoué')
    expect(bodyText()).toContain('pattern never matches')
    expect(w.find('[data-testid="ai-rulegen-save"]').exists()).toBe(false)
  })

  it('jeux de règles indisponibles : ni test ni enregistrement', async () => {
    setUser('admin')
    routes({ available: false })
    const w = await mountIn(AiRuleGenerator, { props: { findingId: F1 } })
    await settle()
    await w.find('form').trigger('submit')
    await settle()
    expect(bodyText()).toContain('ne peut être ni testée ni enregistrée')
    expect(callsTo('POST', '/api/ai/rules/test')).toHaveLength(0)
    expect(w.find('[data-testid="ai-rulegen-save"]').exists()).toBe(false)
  })
})
