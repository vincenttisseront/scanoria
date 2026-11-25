// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// I16 (0.6) dans la console : diagnostic IA d'un sujet de l'appliance, marqué
// « proposé par IA » avec le modèle et son empreinte, action proposée en lien
// vers la page qui porte le bouton, rien de fait automatiquement. Réservé aux
// administrateurs ; sans connecteur, la page reste identique.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, calls, callsTo, clearBody, click, mountIn, resetApi, route, sampleState, setLocale, settle, setUser } from './helpers'
import AiApplianceDiagnosis from '~/components/ai/ApplianceDiagnosis.vue'
import UpdatesPage from '~/pages/updates.vue'
import DashboardPage from '~/pages/index.vue'

const { toastAdd } = vi.hoisted(() => ({ toastAdd: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))

enableAutoUnmount(afterEach)
beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const DIGEST = 'd'.repeat(64)
const PATH = '/api/ai/appliance/diagnosis'
const output = (over: Record<string, unknown> = {}) => ({
  cause: 'health-check', summary: 'Le contrôle de santé du module a échoué.', explanation: 'Le module ne répond pas dans le délai.',
  action: 'retry-install', action_reason: 'Une nouvelle installation relance le contrôle.', steps: ['Vérifier la mémoire libre.'],
  subject: 'install', module: 'trivy', ...over,
})
const done = (out: Record<string, unknown>) => ({
  enabled: true, opt_out: false,
  task: { id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: DIGEST, generated_at: '2026-11-24T09:00:00Z', output: out, feedback: null },
})

describe('diagnostic IA de l\'appliance (I16)', () => {
  it('administrateur : cause, explication, action en lien, marque IA, aucune action faite', async () => {
    setUser('admin')
    route('GET', PATH, () => done(output()))
    const w = await mountIn(AiApplianceDiagnosis, { props: { subjectId: 'install:trivy' } })
    await settle()
    const text = w.text()
    expect(callsTo('GET', PATH)[0]!.query).toEqual({ subject_id: 'install:trivy', locale: 'fr' })
    expect(text).toContain('Diagnostic IA : module trivy')
    expect(text).toContain('contrôle de santé')
    expect(text).toContain('Le module ne répond pas dans le délai.')
    expect(text).toContain('Action proposée : relancer l’installation du module (Catalogue).')
    expect(text).toContain('Aucune action n’est faite automatiquement')
    expect(bodyText()).toContain('proposé par IA · qwen-test:14b (dddddddddddd)')
    expect(w.find('[data-testid="ai-appliance-action"] a').attributes('href')).toBe('/catalog/trivy')
    expect(calls.filter(c => c.method !== 'GET')).toHaveLength(0)
  })

  it('demande : bouton, indicateur d\'attente, sortie affichée sans recharger', async () => {
    setUser('admin')
    let asked = false
    route('GET', PATH, () => (asked ? done(output({ subject: 'update', module: null, cause: 'signature', action: 'import-update' })) : { enabled: true, opt_out: false, task: null }))
    route('POST', PATH, () => {
      asked = true
      return { task_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }
    })
    const w = await mountIn(AiApplianceDiagnosis, { props: { subjectId: 'update:7' } })
    await settle()
    expect(w.text()).toContain('Diagnostic IA : mise à jour n° 7')
    await click(button('Expliquer avec l’IA'))
    await settle()
    expect(callsTo('POST', PATH)[0]!.body).toEqual({ subject_id: 'update:7', locale: 'fr' })
    expect(w.text()).toContain('signature')
    expect(w.find('[data-testid="ai-appliance-action"] a').attributes('href')).toBe('/updates')
  })

  it('action « none » : aucun lien ; titres des alertes', async () => {
    setUser('admin')
    route('GET', PATH, () => done(output({ action: 'none', cause: 'disk', subject: 'alert', module: null })))
    const w = await mountIn(AiApplianceDiagnosis, { props: { subjectId: 'alert:disk:var' } })
    await settle()
    expect(w.text()).toContain('disque /var presque plein')
    expect(w.find('[data-testid="ai-appliance-action"]').exists()).toBe(false)
    for (const [subject, title] of [['alert:disk:root', 'disque / presque plein'], ['alert:update-rollback', 'retour arrière échoué'], ['alert:tls-expiry', 'certificat bientôt expiré'], ['alert:service:scanoria-worker', 'service scanoria-worker'], ['selftest:last', 'dernier selftest']] as const) {
      const x = await mountIn(AiApplianceDiagnosis, { props: { subjectId: subject } })
      await settle()
      expect(x.text()).toContain(title)
    }
  })

  it('non administrateur ou sans connecteur : rien n\'est affiché', async () => {
    setUser('operator')
    const w = await mountIn(AiApplianceDiagnosis, { props: { subjectId: 'selftest:last' } })
    await settle()
    expect(w.text()).toBe('')
    expect(callsTo('GET', PATH)).toHaveLength(0)
    setUser('admin')
    route('GET', PATH, () => ({ enabled: false, opt_out: false, task: null }))
    const x = await mountIn(AiApplianceDiagnosis, { props: { subjectId: 'selftest:last' } })
    await settle()
    expect(x.text()).toBe('')
  })

  it('pages : mises à jour en échec et alertes du tableau de bord, seulement les sujets listés', async () => {
    setUser('admin')
    route('GET', '/api/state', () => sampleState())
    route('GET', '/api/system/updates/history', () => ({ items: [
      { id: '7', action: 'apply', from_version: '0.5.0', to_version: '0.6.0', status: 'failed', code: 'E_UPDATE_SIGNATURE', initiated_by: 'alice', started_at: '2026-11-24T03:00:00Z' },
      { id: '6', action: 'apply', from_version: '0.4.0', to_version: '0.5.0', status: 'success', code: 'OK', initiated_by: 'alice', started_at: '2026-11-20T03:00:00Z' },
    ] }))
    route('GET', '/api/ai/appliance/subjects', () => ({ enabled: true, subjects: ['alert:disk:var', 'selftest:last', 'update:7'] }))
    route('GET', PATH, () => ({ enabled: true, opt_out: false, task: null }))
    const u = await mountIn(UpdatesPage)
    await settle()
    expect(u.text()).toContain('Diagnostic IA : mise à jour n° 7')
    expect(u.text()).not.toContain('mise à jour n° 6')
    expect(u.text()).not.toContain('retour arrière échoué')

    const d = await mountIn(DashboardPage)
    await settle()
    expect(d.text()).toContain('Diagnostic IA : disque /var presque plein')
    expect(d.text()).toContain('Diagnostic IA : dernier selftest')
  })
})
