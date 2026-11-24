// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Sorties IA de la 0.4 dans la console (CLAUDE.md § 3.5) : pré-tri suggéré
// (I3) sans aucun effet sur le statut, résumé d'analyse (I5), type probable
// d'un secret (I14), diagnostic d'un échec avec réglage appliqué par modale
// (I15), traduction de la règle (I17) et retours 👍/👎 (I24). Sans connecteur,
// rien n'est affiché.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, buttons, calls, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import FindingsPage from '~/pages/findings/index.vue'
import AiTriage from '~/components/ai/Triage.vue'
import AiScanSummary from '~/components/ai/ScanSummary.vue'
import AiSecretClass from '~/components/ai/SecretClass.vue'
import AiDiagnosis from '~/components/ai/Diagnosis.vue'
import AiRuleTranslation from '~/components/ai/RuleTranslation.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const P1 = '11111111-1111-4111-8111-111111111111'
const SCAN = '22222222-2222-4222-8222-222222222222'
const F1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const F2 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const DIGEST = 'd'.repeat(64)

function done(id: string, output: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return { enabled: true, opt_out: false, task: { id, status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: DIGEST, generated_at: '2026-11-24T09:00:00Z', output, feedback: null, ...extra } }
}
const TRIAGE = {
  suggestion: 'likely-false-positive',
  summary: 'Valeur de test <b>factice</b>.',
  reasons: [
    { kind: 'test-code', quote: 'tests/fixtures', explanation: 'Fichier de test.', cited: true },
    { kind: 'dummy-value', quote: 'inventé', explanation: 'Citation absente.', cited: false },
  ],
  downgraded: false,
}

/** Sortie selon la tâche demandée (paramètre kind de /api/ai/output). */
function outputs(map: Record<string, unknown>) {
  route('GET', '/api/ai/output', (event) => {
    const kind = new URL(event.node.req.url ?? '/', 'http://x').searchParams.get('kind') ?? ''
    return map[kind] ?? { enabled: true, opt_out: false, task: null }
  })
}

describe('pré-tri suggéré (I3) et retours (I24)', () => {
  const base = {
    project_id: P1, project_slug: 'demo', project_name: 'Démo', fingerprint: 'f'.repeat(64), category: 'sast', native_severity: 'high',
    path: 'tests/fixtures/app.py', start_line: 3, vuln_ids: [], package: null, malicious: false, secret_type: null, secret_state: null,
    status_until: null, is_new: true, first_seen_at: '2026-11-24T08:00:00Z', updated_at: '2026-11-24T08:00:00Z', tool: 'bandit', severity: 'high',
  }
  const ROWS = [
    { ...base, id: F1, rule_id: 'B105', title: 'Possible hardcoded password', status: 'new' },
    { ...base, id: F2, rule_id: 'B106', title: 'Autre', status: 'confirmed' },
  ]
  const detail = {
    ...ROWS[0], message: 'm', end_line: 3, snippet: null, cwe: [], status_reason: null, status_by: null, status_at: null,
    secret_state_by: null, secret_state_at: null, first_commit: null, last_commit: null, accepted_expired: false, revoke_pending_days: null, scans: [],
  }

  it('badge dans la liste et suggestion dans le détail, sans aucun appel de tri', async () => {
    setUser('operator')
    route('GET', '/api/findings', () => ({ items: ROWS, total: 2 }))
    route('GET', '/api/findings/summary', () => ({ projects: [] }))
    route('GET', `/api/findings/${F1}`, () => detail)
    route('GET', '/api/ai/suggestions', () => ({ enabled: true, items: { [F1]: { value: 'likely-false-positive', model: 'qwen-test:14b', model_digest: DIGEST } } }))
    route('GET', '/api/ai/rule-key', () => ({ key: 'bandit:1.8.0:B105' }))
    route('POST', '/api/ai/explain', () => ({ task_id: null }))
    outputs({ 'triage-finding': done('t-triage', TRIAGE) })
    route('POST', '/api/ai/feedback', () => ({ ok: true }))

    const w = await mountIn(FindingsPage)
    await settle()
    // Seuls les résultats « nouveau » sont demandés.
    expect(callsTo('GET', '/api/ai/suggestions')[0]!.query).toEqual({ kind: 'triage-finding', ids: F1 })
    const badges = document.body.querySelectorAll('[data-testid="ai-triage-badge"]')
    expect(badges).toHaveLength(1)
    expect(badges[0]!.textContent).toContain('IA : faux positif probable')

    await w.findAll('tbody tr')[0]!.trigger('click')
    await settle()
    const panel = document.body.querySelector('[data-testid="ai-triage"]')!
    expect(panel.textContent).toContain('faux positif probable')
    expect(panel.textContent).toContain('Valeur de test <b>factice</b>.')
    expect(panel.querySelector('b')).toBeNull()
    expect(panel.textContent).toContain('tests/fixtures')
    expect(panel.textContent).not.toContain('inventé')
    expect(bodyText()).toContain(`proposé par IA · qwen-test:14b (${'d'.repeat(12)})`)
    expect(bodyText()).toContain('le statut ne change que par votre clic')

    await click(document.body.querySelector('[data-testid="ai-panel-triage-finding"] [data-testid="ai-vote-up"]')!)
    expect(callsTo('POST', '/api/ai/feedback').map(c => c.body)).toEqual([{ task_id: 't-triage', vote: 1 }])
    // La suggestion n'a déclenché aucun changement de statut.
    expect(calls.filter(c => c.path.includes('/status') || c.path.includes('/secret'))).toHaveLength(0)
  })

  it('correction dans une modale, refus du serveur signalé ; rien sans connecteur', async () => {
    setUser('viewer')
    outputs({ 'triage-finding': done('t-triage', { ...TRIAGE, suggestion: 'to-confirm', downgraded: true }, { feedback: { vote: 1, correction: null } }) })
    let fail = false
    route('POST', '/api/ai/feedback', () => {
      if (fail) throw Object.assign(new Error('x'), { statusCode: 409, data: { code: 'E_CONFLICT' } })
      return { ok: true }
    })
    await mountIn(AiTriage, { props: { findingId: F1 } })
    await settle()
    expect(bodyText()).toContain('ramenée à « à confirmer »')
    expect(document.body.querySelector('[data-testid="ai-vote-up"]')!.className).toBeTruthy()
    await click(document.body.querySelector('[data-testid="ai-correct"]')!)
    expect(bodyText()).toContain('Corriger la sortie de l’IA')
    const area = document.body.querySelector<HTMLTextAreaElement>('[role="dialog"] textarea')!
    area.value = 'C’est un vrai mot de passe.'
    area.dispatchEvent(new Event('input', { bubbles: true }))
    await settle()
    await click(button('Enregistrer'))
    expect(callsTo('POST', '/api/ai/feedback').at(-1)!.body).toEqual({ task_id: 't-triage', vote: -1, correction: 'C’est un vrai mot de passe.' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success' }))

    fail = true
    await click(document.body.querySelector('[data-testid="ai-vote-down"]')!)
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ color: 'error' }))
    resetApi()
    clearBody()

    route('GET', '/api/ai/output', () => ({ enabled: false, opt_out: false, task: null }))
    const w = await mountIn(AiTriage, { props: { findingId: F1 } })
    await settle()
    expect(w.find('[data-testid="ai-panel-triage-finding"]').exists()).toBe(false)
  })
})

describe('résumé (I5), secret (I14), traduction (I17)', () => {
  it('résumé : priorités avec liens internes seulement', async () => {
    setUser('viewer')
    outputs({
      'summarize-scan': done('t-sum', {
        headline: '2 nouveaux résultats élevés.',
        changes: '2 nouveaux, 1 corrigé.',
        priorities: [
          { ref: 1, why: 'Injection SQL', severity: 'high', finding_id: F1, link: `/findings?scan=${SCAN}&ids=${F1}` },
          { ref: 2, why: 'Lien piégé', link: 'https://evil.exemple.test/' },
        ],
        blocking: 'Rien ne bloque.',
        not_covered: 'Aucun fichier de verrouillage.',
      }),
    })
    const w = await mountIn(AiScanSummary, { props: { scanId: SCAN } })
    await settle()
    const text = w.text()
    expect(text).toContain('Résumé de l’analyse')
    expect(text).toContain('2 nouveaux résultats élevés.')
    expect(text).toContain('Injection SQL')
    expect(text).toContain('Aucun fichier de verrouillage.')
    expect(w.findAll('a').map(a => a.attributes('href'))).toEqual([`/findings?scan=${SCAN}&ids=${F1}`])
  })

  it('secret : affiché seulement s’il a été précalculé, jamais demandé', async () => {
    setUser('viewer')
    outputs({ 'classify-secret': done('t-sec', { class: 'internal-token', confidence: 'medium', summary: 'Jeton d’un service interne.', reasons: ['Fichier .env'] }) })
    const w = await mountIn(AiSecretClass, { props: { findingId: F2 } })
    await settle()
    expect(w.text()).toContain('jeton interne')
    expect(w.text()).toContain('confiance moyenne')
    expect(w.text()).toContain('sans la valeur')
    resetApi()

    outputs({})
    const w2 = await mountIn(AiSecretClass, { props: { findingId: F2 } })
    await settle()
    expect(w2.find('[data-testid="ai-panel-classify-secret"]').exists()).toBe(false)
    expect(buttons('Expliquer avec l’IA')).toHaveLength(0)
  })

  it('traduction : clé calculée par le serveur, demandée d’elle-même, original affiché ; rien en anglais', async () => {
    setUser('viewer')
    let asked = false
    route('GET', '/api/ai/rule-key', () => ({ key: 'bandit:1.8.0:B105' }))
    route('POST', '/api/ai/explain', () => {
      asked = true
      return { task_id: 't-tr' }
    })
    route('GET', '/api/ai/output', () => (asked
      ? done('t-tr', { translation: 'Mot de passe codé en dur possible' })
      : { enabled: true, opt_out: false, task: null }))
    const w = await mountIn(AiRuleTranslation, { props: { findingId: F1, original: 'Possible hardcoded password' } })
    await settle()
    expect(callsTo('POST', '/api/ai/explain')[0]!.body).toEqual({ kind: 'translate-rule', subject_id: 'bandit:1.8.0:B105', locale: 'fr' })
    expect(callsTo('GET', '/api/ai/output').at(-1)!.query).toMatchObject({ kind: 'translate-rule', subject_id: 'bandit:1.8.0:B105' })
    expect(w.text()).toContain('Mot de passe codé en dur possible')
    expect(w.text()).toContain('Texte d’origine : Possible hardcoded password')
    resetApi()

    await setLocale('en')
    route('GET', '/api/ai/rule-key', () => ({ key: 'bandit:1.8.0:B105' }))
    const w2 = await mountIn(AiRuleTranslation, { props: { findingId: F1, original: 'x' } })
    await settle()
    expect(callsTo('GET', '/api/ai/rule-key')).toHaveLength(0)
    expect(w2.text()).toBe('')
  })
})

describe('diagnostic d’un échec (I15)', () => {
  const DIAG = { cause: 'timeout', module: 'trivy', summary: 'Trivy a dépassé son délai.', fix: 'Allonger le délai.', steps: ['Relancer l’analyse'], proposal: null }

  it('opérateur : réglage recalculé par le serveur, appliqué par une modale', async () => {
    setUser('operator')
    outputs({ 'diagnose-scan': done('t-diag', DIAG) })
    route('GET', '/api/ai/diagnosis/proposal', () => ({ proposal: { kind: 'timeout', module: 'trivy', current_s: 900, proposed_s: 1800 }, overrides: {} }))
    route('POST', '/api/ai/diagnosis/apply', () => ({ ok: true }))
    const w = await mountIn(AiDiagnosis, { props: { scanId: SCAN } })
    await settle()
    expect(w.text()).toContain('délai dépassé')
    expect(w.text()).toContain('Relancer l’analyse')
    expect(w.text()).toContain('délai de trivy porté de 15 min à 30 min')
    await click(document.body.querySelector('[data-testid="ai-diagnosis-apply"]')!)
    expect(bodyText()).toContain('Allonger le délai de trivy ?')
    expect(callsTo('POST', '/api/ai/diagnosis/apply')).toHaveLength(0)
    await click(button('Appliquer ce réglage'))
    expect(callsTo('POST', '/api/ai/diagnosis/apply')[0]!.body).toEqual({ scan_id: SCAN, module: 'trivy', proposed_s: 1800 })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'success', title: 'Délai de trivy porté à 30 min.' }))
    expect(document.body.querySelector('[data-testid="ai-diagnosis-proposal"]')).toBeNull()
  })

  it('lecteur : diagnostic sans réglage ; refus du serveur signalé', async () => {
    setUser('viewer')
    outputs({ 'diagnose-scan': done('t-diag', DIAG) })
    const w = await mountIn(AiDiagnosis, { props: { scanId: SCAN } })
    await settle()
    expect(w.text()).toContain('Trivy a dépassé son délai.')
    expect(callsTo('GET', '/api/ai/diagnosis/proposal')).toHaveLength(0)
    resetApi()
    clearBody()

    setUser('operator')
    outputs({ 'diagnose-scan': done('t-diag', DIAG) })
    route('GET', '/api/ai/diagnosis/proposal', () => ({ proposal: { kind: 'timeout', module: 'trivy', current_s: 900, proposed_s: 1800 }, overrides: {} }))
    route('POST', '/api/ai/diagnosis/apply', () => {
      throw Object.assign(new Error('stale'), { statusCode: 409, statusMessage: 'E_AI_STALE', data: { code: 'E_AI_STALE' } })
    })
    await mountIn(AiDiagnosis, { props: { scanId: SCAN } })
    await settle()
    await click(document.body.querySelector('[data-testid="ai-diagnosis-apply"]')!)
    await click(button('Appliquer ce réglage'))
    expect(toastAdd).toHaveBeenLastCalledWith(expect.objectContaining({ color: 'error' }))
  })
})
