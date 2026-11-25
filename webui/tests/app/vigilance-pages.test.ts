// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Écrans de vigilance (0.6, chantier B) : bandeau « module X vulnérable, mise
// à jour disponible » et canaris en échec (F19, G14), panneau de Mises à jour
// (relevé et canaris relancés avec indicateur d'attente), fiche d'un module
// (canari, essai F13 démarré, adopté ou abandonné par des modales de la
// console), versions figées d'un projet (G6, motif obligatoire), anglais.

import { createError } from 'h3'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import Banner from '~/components/vigilance/Banner.vue'
import AppliancePanel from '~/components/vigilance/AppliancePanel.vue'
import ModulePanel from '~/components/vigilance/ModulePanel.vue'
import ProjectPins from '~/components/vigilance/ProjectPins.vue'
import type { TrialView, VigilanceSummary } from '~/utils/vigilance'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  setUser('admin')
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const canary = (ok: boolean, over: Record<string, unknown> = {}) => ({
  module_id: 'gitleaks', module_version: '8.30.0', ok, duration_ms: 1200, run_at: '2026-11-24T02:31:00Z',
  details: { expect: [{ rule: 'aws-access-token', category: 'secrets', min: 1, found: ok ? 2 : 0, ok }] }, ...over,
})
function summary(patch: Partial<VigilanceSummary> = {}): VigilanceSummary {
  return {
    available: true,
    self_sbom: { at: '2026-11-24T05:00:00Z', gaps: ['matcher-missing'], subjects: [
      { subject: 'console', version: '0.6.0', components: 412, error: null, tools: [{ id: 'grype', version: '0.90.0', ok: true }] },
      { subject: 'module:gitleaks', version: '8.30.0', components: 37, error: null, tools: [{ id: 'grype', version: '0.90.0', ok: true }] },
    ] },
    vulns: [{ subject: 'module:gitleaks', critical: 1, high: 2, medium: 0, low: 0, info: 0, update_available: '8.30.1' }],
    alerts: [{ subject: 'module:gitleaks', update_available: '8.30.1', critical: 1, high: 2, total: 3 }],
    canaries: { latest: [canary(false)], failing: ['gitleaks'] },
    retained: [], trials: [],
    ...patch,
  }
}
const trial = (over: Partial<TrialView> = {}): TrialView => ({
  id: '0b6f9c2e-1d3a-4c5b-8e7f-9a0b1c2d3e4f', module_id: 'gitleaks', from_version: '8.30.0', to_version: '8.30.1', status: 'done', sample_size: 3,
  summary: { new: 1, gone: 2, unchanged: 5, scans: 3, failed: 0, duration_old_ms: 5000, duration_new_ms: 4000,
    per_scan: [{ trial_scan_id: 's1', new_examples: [{ rule: 'private-key', path: 'c.pem' }], gone_examples: [] }] },
  started_at: '2026-11-24T09:00:00Z', finished_at: '2026-11-24T09:10:00Z', progress: { total: 3, finished: 3 }, ...over,
})
function helperOk(path: string, id: string) {
  route('POST', path, () => ({ request_id: id }))
  route('GET', `/api/requests/${id}`, () => ({ id, type: 'x', status: 'ok', code: 'OK', step: null, message: null, output: null }))
}
async function waitRequests(rounds = 4) {
  for (let i = 0; i < rounds; i++) await vi.advanceTimersByTimeAsync(5100)
  await settle()
}

describe('bandeau de vigilance', () => {
  it('module vulnérable avec mise à jour, canari en échec, liens vers la fiche', async () => {
    route('GET', '/api/vigilance', () => summary())
    await mountIn(Banner)
    await settle()
    const text = bodyText()
    expect(text).toContain('mise à jour disponible : 8.30.1')
    expect(text).toContain('Canari en échec (1 module(s))')
    expect(document.body.querySelector('a[href="/catalog/gitleaks"]')).not.toBeNull()
  })
  it('rien à signaler ou lecture en échec : aucun bandeau', async () => {
    route('GET', '/api/vigilance', () => summary({ alerts: [], canaries: { latest: [], failing: [] } }))
    await mountIn(Banner)
    await settle()
    expect(document.body.querySelector('[data-testid="vigilance-vuln-banner"]')).toBeNull()
    resetApi()
    route('GET', '/api/vigilance', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(Banner)
    await settle()
    expect(document.body.querySelector('[data-testid="vigilance-canary-banner"]')).toBeNull()
  })
})

describe('panneau de vigilance (Mises à jour)', () => {
  it('relevé, trous de couverture, détail d’un sujet, relance avec indicateur d’attente', async () => {
    let n = 0
    route('GET', '/api/vigilance', () => {
      n++
      return summary()
    })
    route('GET', '/api/vigilance/self-vulns', () => ({ subject: 'module:gitleaks', vulns: [
      { vuln_id: 'CVE-2026-0001', purl: 'pkg:golang/golang.org/x/net@0.1.0', severity: 'critical', fixed_version: '0.2.0', first_seen: '2026-11-24T05:00:00Z' },
    ] }))
    helperOk('/api/vigilance/self-sbom', 'r-sbom')
    const w = await mountIn(AppliancePanel)
    await settle()
    expect(bodyText()).toContain('Ni Grype ni OSV-Scanner installés')
    expect(bodyText()).toContain('412')
    await click(button('gitleaks 8.30.0'))
    await settle()
    expect(bodyText()).toContain('CVE-2026-0001')
    expect(bodyText()).toContain('→ 0.2.0')
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    await click(button('Relever maintenant'))
    expect(document.body.querySelector('[role="status"]')).not.toBeNull()
    await waitRequests()
    expect(callsTo('POST', '/api/vigilance/self-sbom')).toHaveLength(1)
    expect(n).toBe(2)
    expect(w.emitted('changed')).toHaveLength(1)
  })
  it('lecteur : aucun bouton de relance ; jamais relevé', async () => {
    setUser('viewer')
    route('GET', '/api/vigilance', () => summary({ self_sbom: null }))
    await mountIn(AppliancePanel)
    await settle()
    expect(buttons('Relever maintenant')).toHaveLength(0)
    expect(bodyText()).toContain('Aucun relevé pour l’instant')
  })
})

describe('fiche d’un module', () => {
  const url = '/api/catalog/modules/gitleaks/vigilance'
  const view = (over: Record<string, unknown> = {}) => ({
    canaries: [canary(false), canary(true, { run_at: '2026-11-23T02:31:00Z' })], trials: [trial()], trial_candidates: ['8.30.1'],
    pins: [{ project_id: 'p1', slug: 'api', name: 'API', version: '8.30.0', reason: 'audit de la release' }],
    vulns: [{ vuln_id: 'CVE-2026-0001', purl: 'pkg:golang/x@1', severity: 'high', fixed_version: null, first_seen: '2026-11-24T05:00:00Z' }],
    ...over,
  })

  it('canari en échec : attendu manquant, module jamais désactivé ; essai terminé et son écart', async () => {
    route('GET', url, () => view())
    await mountIn(ModulePanel, { props: { moduleId: 'gitleaks', isAdmin: true, scanner: true } })
    await settle()
    const text = bodyText()
    expect(text).toContain('aws-access-token : 0 trouvé(s) pour 1 attendu(s)')
    expect(text).toContain('Le module n’est pas désactivé')
    expect(text).toContain('1 nouveau(x), 2 disparu(s), 5 inchangé(s) sur 3 analyse(s)')
    expect(text).toContain('5.0 s → 4.0 s')
    expect(text).toContain('+ private-key c.pem')
    expect(text).toContain('audit de la release')
    expect(text).toContain('CVE-2026-0001')
  })

  it('essai : démarré par une modale, suivi, puis adoption confirmée (mise à jour normale)', async () => {
    let trials = [] as TrialView[]
    route('GET', url, () => view({ trials }))
    helperOk('/api/catalog/modules/gitleaks/trials', 'r-trial')
    helperOk(`/api/catalog/modules/gitleaks/trials/${trial().id}/adopt`, 'r-adopt')
    const w = await mountIn(ModulePanel, { props: { moduleId: 'gitleaks', isAdmin: true, scanner: true } })
    await settle()
    await click(button('Essayer'))
    expect(bodyText()).toContain('Rien n’est modifié tant que vous n’adoptez pas')
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'] })
    trials = [trial({ status: 'running', summary: null, progress: { total: 3, finished: 1 } })]
    await click(button('Essayer'))
    await waitRequests()
    expect(callsTo('POST', '/api/catalog/modules/gitleaks/trials')[0]!.body).toEqual({ version: '8.30.1', sample_size: 3 })
    expect(bodyText()).toContain('1 analyse(s) terminée(s) sur 3')
    // Suivi sans recharger la page, puis essai terminé.
    trials = [trial()]
    await vi.advanceTimersByTimeAsync(10_100)
    await settle()
    expect(bodyText()).toContain('Terminé')
    await click(button('Adopter'))
    expect(bodyText()).toContain('Adopter la version 8.30.1')
    await click(button('Adopter'))
    await waitRequests()
    expect(callsTo('POST', `/api/catalog/modules/gitleaks/trials/${trial().id}/adopt`)).toHaveLength(1)
    expect(w.emitted('changed')).toBeTruthy()
  })

  it('abandon confirmé ; refus du serveur traduit ; canari relancé', async () => {
    route('GET', url, () => view())
    route('POST', `/api/catalog/modules/gitleaks/trials/${trial().id}/abandon`, () => {
      throw createError({ statusCode: 409, statusMessage: 'E_PRECONDITION', data: { code: 'E_PRECONDITION', reason: 'E_TRIAL_STATE' } })
    })
    helperOk('/api/vigilance/canaries', 'r-canary')
    await mountIn(ModulePanel, { props: { moduleId: 'gitleaks', isAdmin: true, scanner: true } })
    await settle()
    await click(button('Abandonner'))
    expect(bodyText()).toContain('l’image candidate est retirée')
    await click(button('Abandonner'))
    await settle()
    expect(callsTo('POST', `/api/catalog/modules/gitleaks/trials/${trial().id}/abandon`)).toHaveLength(1)
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    await click(button('Rejouer le canari'))
    await waitRequests()
    expect(callsTo('POST', '/api/vigilance/canaries')[0]!.body).toEqual({ ids: ['gitleaks'] })
  })

  it('lecteur, aucune candidate : aucune action, en anglais', async () => {
    await setLocale('en')
    setUser('viewer')
    route('GET', url, () => view({ canaries: [], trials: [], trial_candidates: [], pins: [], vulns: [] }))
    await mountIn(ModulePanel, { props: { moduleId: 'gitleaks', isAdmin: false, scanner: true } })
    await settle()
    expect(bodyText()).toContain('No newer version in the catalog.')
    expect(bodyText()).toContain('No canary replayed yet.')
    expect(buttons('Try')).toHaveLength(0)
    expect(buttons('Replay canary')).toHaveLength(0)
  })
})

describe('versions figées d’un projet', () => {
  const url = '/api/projects/p1/pins'
  it('figer avec un motif, avertissements, libérer par une modale', async () => {
    let pins: unknown[] = []
    route('GET', url, () => ({ pins, pinnable: [{ id: 'gitleaks', version: '8.30.0' }] }))
    route('PUT', `${url}/gitleaks`, () => {
      pins = [{ module_id: 'gitleaks', version: '8.30.0', reason: 'audit 2.4', pinned_at: '2026-11-24T09:00:00Z', installed_version: '8.30.1', warnings: ['retired', 'missing'] }]
      return { pin: pins[0] }
    })
    route('DELETE', `${url}/gitleaks`, () => {
      pins = []
      return { ok: true }
    })
    const w = await mountIn(ProjectPins, { props: { projectId: 'p1', isAdmin: true } })
    await settle()
    expect(bodyText()).toContain('Aucune version figée')
    await click(button('Figer une version'))
    // Sans motif suffisant, rien n'est envoyé.
    await click(button('Figer une version'))
    expect(callsTo('PUT', `${url}/gitleaks`)).toHaveLength(0)
    const vm = w.vm as unknown as { reason: string }
    vm.reason = 'audit 2.4'
    await settle()
    await click(button('Figer une version'))
    expect(callsTo('PUT', `${url}/gitleaks`)[0]!.body).toEqual({ reason: 'audit 2.4' })
    expect(bodyText()).toContain('retirée du catalogue')
    expect(bodyText()).toContain('image absente : analyses non concluantes')
    await click(button('Libérer'))
    expect(bodyText()).toContain('Le projet suivra de nouveau la version installée')
    await click(button('Libérer'))
    expect(callsTo('DELETE', `${url}/gitleaks`)).toHaveLength(1)
    expect(bodyText()).toContain('Aucune version figée')
  })
  it('refus du serveur traduit ; lecteur sans action', async () => {
    route('GET', url, () => ({ pins: [], pinnable: [{ id: 'gitleaks', version: '8.30.0' }] }))
    route('PUT', `${url}/gitleaks`, () => {
      throw createError({ statusCode: 409, statusMessage: 'E_PRECONDITION', data: { code: 'E_PRECONDITION', reason: 'E_PIN_IMAGE' } })
    })
    const w = await mountIn(ProjectPins, { props: { projectId: 'p1', isAdmin: true } })
    await settle()
    await click(button('Figer une version'))
    ;(w.vm as unknown as { reason: string }).reason = 'motif valable'
    await settle()
    await click(button('Figer une version'))
    expect(callsTo('PUT', `${url}/gitleaks`)).toHaveLength(1)
    setUser('viewer')
    resetApi()
    route('GET', url, () => ({ pins: [], pinnable: [{ id: 'gitleaks', version: '8.30.0' }] }))
    clearBody()
    await mountIn(ProjectPins, { props: { projectId: 'p1', isAdmin: false } })
    await settle()
    expect(buttons('Figer une version')).toHaveLength(0)
  })
})
