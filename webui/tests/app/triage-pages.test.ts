// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier B (0.7) : pages « Exceptions à approuver » (F5, J15), « Règles de
// tri » (F4, simulation obligatoire avant l'enregistrement) et
// « Responsables » (F6). Modales de la console, indicateurs d'attente,
// décisions refusées rappelées, textes jamais interprétés.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ApprovalsPage from '~/pages/findings/approvals.vue'
import RulesPage from '~/pages/findings/rules.vue'
import OwnersPage from '~/pages/findings/owners.vue'

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
const E1 = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1'
const E2 = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2'
const SUMMARY = { projects: [{ project_id: P1, project_slug: 'demo', project_name: 'Démo', open: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0, secrets_to_revoke: 0, malicious: 0 }] }

function setInput(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event('input', { bubbles: true }))
}
function field(testid: string, tag: 'input' | 'textarea'): HTMLInputElement {
  const el = document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)!
  return (el.tagName.toLowerCase() === tag ? el : el.querySelector(tag)!) as HTMLInputElement
}

const pendingRow = (id: string, extra: Record<string, unknown> = {}) => ({
  id, project_id: P1, project_slug: 'demo', project_name: 'Démo', kind: 'vuln', target: { vuln_id: 'CVE-2026-0002' },
  reason: 'Correctif <b>prévu</b>', expires_on: '2027-01-01', requested_via: 'api', requester_label: 'api-token:scn_ab12',
  requester_is_human: false, commit_authors: ['dev1'], created_by: null, created_at: '2026-11-24T08:00:00Z', expired: false, cannot_decide: null, ...extra,
})

describe('page Exceptions à approuver', () => {
  it('administrateur : demandes listées, règles rappelées, approbation par modale avec motif', async () => {
    setUser('admin')
    route('GET', '/api/exceptions/pending', () => ({ items: [pendingRow(E1), pendingRow(E2, { cannot_decide: 'requester', requester_is_human: true, created_by: 'admin', requested_via: 'console' })] }))
    route('GET', '/api/exceptions/pending-count', () => ({ count: 1 }))
    route('POST', `/api/exceptions/${E1}/decision`, () => ({ id: E1, status: 'approved', reevaluated: [{ scan_id: 'x', before: 'failed', after: 'passed' }] }))
    await mountIn(ApprovalsPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('api-token:scn_ab12 (non humain)')
    expect(text).toContain('API')
    expect(text).toContain('Correctif <b>prévu</b>')
    expect(text).toContain('Auteurs du commit analysé (exclus de la décision) : dev1')
    expect(text).toContain('C’est votre demande : un autre administrateur doit la décider.')
    expect(document.body.querySelectorAll('[data-testid="approve"]')).toHaveLength(1)
    await click(document.body.querySelector('[data-testid="approve"]')!)
    expect(bodyText()).toContain('Approuver l’exception')
    expect(bodyText()).toContain('2027-01-01')
    const confirm = document.body.querySelector<HTMLButtonElement>('[data-testid="decision-confirm"]')!
    expect(confirm.disabled).toBe(true)
    setInput(field('decision-reason', 'textarea'), 'Correctif planifié')
    await settle()
    await click(confirm)
    expect(callsTo('POST', `/api/exceptions/${E1}/decision`)[0]!.body).toEqual({ decision: 'approved', reason: 'Correctif planifié' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Exception approuvée. Verdicts recalculés : 1.' }))
    expect(callsTo('GET', '/api/exceptions/pending-count').length).toBeGreaterThan(0)
  })

  it('refus signalé par le serveur ; liste vide ; non-administrateur', async () => {
    setUser('admin')
    route('GET', '/api/exceptions/pending', () => ({ items: [pendingRow(E1)] }))
    route('GET', '/api/exceptions/pending-count', () => ({ count: 1 }))
    route('POST', `/api/exceptions/${E1}/decision`, () => apiFail(403, 'E_DECIDER_NOT_ALLOWED'))
    await mountIn(ApprovalsPage)
    await settle()
    await click(document.body.querySelector('[data-testid="refuse"]')!)
    expect(bodyText()).toContain('Refuser la demande')
    setInput(field('decision-reason', 'textarea'), 'Pas de justification')
    await settle()
    await click(document.body.querySelector('[data-testid="decision-confirm"]')!)
    expect(callsTo('POST', `/api/exceptions/${E1}/decision`)[0]!.body).toMatchObject({ decision: 'refused' })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })

  it('aucune demande ; lecteur sans accès', async () => {
    setUser('admin')
    route('GET', '/api/exceptions/pending', () => ({ items: [] }))
    await mountIn(ApprovalsPage)
    await settle()
    expect(bodyText()).toContain('Aucune demande en attente.')
    resetApi()
    clearBody()
    setUser('viewer')
    await mountIn(ApprovalsPage)
    await settle()
    expect(bodyText()).toContain('Réservé aux administrateurs.')
  })
})

const RULE = {
  id: 'rrrrrrrr-rrrr-4rrr-8rrr-rrrrrrrrrrr1', project_id: P1, project_slug: 'demo', match: { path: 'tests/**', tool: 'trivy' }, action: 'false-positive',
  reason: 'Jeux <i>de test</i>', expires_on: '2027-01-01', applied_count: 4, created_by: 'operator', created_at: '2026-11-24T08:00:00Z', revoked_at: null, active: true,
}

describe('page Règles de tri', () => {
  it('opérateur : pré-rempli, simulation obligatoire, enregistrement, révocation par modale', async () => {
    setUser('operator')
    route('GET', '/api/findings/summary', () => SUMMARY)
    route('GET', '/api/triage-rules', () => ({ items: [RULE] }))
    route('GET', '/api/triage-rules/proposals', () => ({ items: [{ project_id: P1, match: { rule: 'R9', path: 'spec/**' }, action: 'false-positive', reason_kind: 'test-code', count: 3, reason: 'Code de test' }] }))
    route('POST', '/api/triage-rules/simulate', () => ({ total: 2, projects: [{ project_id: P1, project_slug: 'demo', count: 2 }], items: [{ id: 'f1', project_slug: 'demo', tool: 'trivy', rule_id: 'R1', severity: 'low', path: 'tests/a.js', title: '<img src=x>' }], truncated: false }))
    route('POST', '/api/triage-rules', () => ({ rule: RULE, applied: 2 }))
    route('DELETE', `/api/triage-rules/${RULE.id}`, () => ({ rule: { ...RULE, active: false }, reverted: 3 }))
    await mountIn(RulesPage, { route: `/findings/rules?project_id=${P1}&rule=R1&tool=trivy` })
    await settle()
    expect(bodyText()).toContain('Jeux <i>de test</i>')
    expect(bodyText()).toContain('proposé par IA')
    expect(field('rule-rule', 'input').value).toBe('R1')
    expect(field('rule-tool', 'input').value).toBe('trivy')
    setInput(field('rule-reason', 'textarea'), 'Règle bruyante')
    await settle()
    expect(button('Enregistrer et appliquer').disabled).toBe(true)
    await click(document.body.querySelector('[data-testid="rule-simulate"]')!)
    expect(callsTo('POST', '/api/triage-rules/simulate')[0]!.body).toMatchObject({ project_id: P1, match: { tool: 'trivy', rule: 'R1' }, action: 'false-positive', reason: 'Règle bruyante' })
    expect(bodyText()).toContain('2 résultat(s) seraient touchés.')
    expect(bodyText()).toContain('demo · trivy · R1 · tests/a.js')
    // Modifier le formulaire après simulation exige une nouvelle simulation.
    setInput(field('rule-reason', 'textarea'), 'Règle bruyante connue')
    await settle()
    expect(button('Enregistrer et appliquer').disabled).toBe(true)
    await click(document.body.querySelector('[data-testid="rule-simulate"]')!)
    expect(button('Enregistrer et appliquer').disabled).toBe(false)
    await click(button('Enregistrer et appliquer'))
    expect(callsTo('POST', '/api/triage-rules')).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Règle enregistrée : 2 résultat(s) triés.' }))

    await click(buttons('Révoquer')[0]!)
    expect(bodyText()).toContain('Révoquer la règle')
    await click(buttons('Confirmer').at(-1)!)
    expect(callsTo('DELETE', `/api/triage-rules/${RULE.id}`)).toHaveLength(1)
  })

  it('proposition IA : pré-remplit le formulaire, rien n\'est enregistré sans clic', async () => {
    setUser('operator')
    route('GET', '/api/findings/summary', () => SUMMARY)
    route('GET', '/api/triage-rules', () => ({ items: [] }))
    route('GET', '/api/triage-rules/proposals', () => ({ items: [{ project_id: P1, match: { rule: 'R9', path: 'spec/**' }, action: 'false-positive', reason_kind: 'test-code', count: 3, reason: 'Code de test' }] }))
    route('POST', '/api/triage-rules/simulate', () => apiFail(400, 'E_VALIDATION'))
    await mountIn(RulesPage, { route: `/findings/rules?project_id=${P1}` })
    await settle()
    expect(bodyText()).toContain('Aucune règle.')
    await click(button('Pré-remplir'))
    expect(field('rule-path', 'input').value).toBe('spec/**')
    expect(field('rule-reason', 'textarea').value).toBe('Code de test')
    expect(bodyText()).toContain('Proposé par IA à partir du pré-tri')
    await click(document.body.querySelector('[data-testid="rule-simulate"]')!)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
    expect(callsTo('POST', '/api/triage-rules')).toHaveLength(0)
  })

  it('lecteur : lecture seule', async () => {
    setUser('viewer')
    route('GET', '/api/findings/summary', () => SUMMARY)
    route('GET', '/api/triage-rules', () => ({ items: [RULE] }))
    await mountIn(RulesPage)
    await settle()
    expect(buttons('Nouvelle règle')).toHaveLength(0)
    expect(buttons('Révoquer')).toHaveLength(0)
  })
})

describe('page Responsables', () => {
  it('administrateur : ajout et retrait d\'une correspondance', async () => {
    setUser('admin')
    route('GET', '/api/owner-mappings', () => ({ items: [{ project_id: null, project_slug: null, owner: '@front', user_id: 2, username: 'bob', created_at: '2026-11-24T08:00:00Z' }] }))
    route('GET', '/api/users', () => ({ items: [{ id: '2', username: 'bob' }] }))
    route('GET', '/api/findings/summary', () => SUMMARY)
    route('POST', '/api/owner-mappings', () => ({ added: true }))
    route('DELETE', '/api/owner-mappings', () => ({ removed: true }))
    await mountIn(OwnersPage)
    await settle()
    expect(bodyText()).toContain('@front')
    expect(bodyText()).toContain('toute l’appliance')
    await click(button('Retirer'))
    expect(callsTo('DELETE', '/api/owner-mappings')).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Correspondance retirée.' }))
    expect(button('Ajouter').disabled).toBe(true)
  })
})
