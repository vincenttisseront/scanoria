// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Section Analyses : file en direct et historique filtrable, détail d'une
// analyse (plan figé et raisons, modules, journal, couverture, verdict brut),
// annuler, relancer et rejouer par une modale de la console.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ScansPage from '~/pages/scans/index.vue'
import ScanPage from '~/pages/scans/[id].vue'
import type { ScanDetail, ScanSummary } from '~/composables/useScans'

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

const ID = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'
const NEW_ID = '8b2d4f6a-1c3e-4a5b-8c7d-9e0f1a2b3c4d'

function summary(patch: Partial<ScanSummary> = {}): ScanSummary {
  return {
    id: ID, project_id: 'p1', project_name: 'Boutique', project_slug: 'boutique', number: 7, trigger: 'schedule',
    priority: 10, effective_priority: 14, ref: 'main', commit_sha: null, profile: 'rapide', status: 'queued', verdict: null,
    attempt: 1, error: null, replay_of: null, queued_at: '2026-11-24T08:00:00Z', started_at: null, finished_at: null, ...patch,
  }
}

function detail(patch: Partial<ScanDetail> = {}): ScanDetail {
  return {
    ...summary({ status: 'done', verdict: 'failed', commit_sha: 'c'.repeat(40), started_at: '2026-11-24T08:01:00Z', finished_at: '2026-11-24T08:03:00Z' }),
    gate: 'defaut',
    plan: {
      source: { kind: 'git', ref: 'main', commit: 'c'.repeat(40), history: 'full' },
      profile: { slug: 'rapide', categories: ['secrets', 'sca', 'lint'] },
      gate: { slug: 'defaut' },
      modules: [
        { id: 'gitleaks', version: '8.30.1', image_digest: `sha256:${'a'.repeat(64)}`, categories: ['secrets'], options: {}, feeds: [], timeout_s: 900, history: 'full', reason: 'category' },
        { id: 'trivy', version: '0.76.2', image_digest: null, categories: ['sca', 'iac'], options: {}, feeds: [], timeout_s: 600, history: 'shallow', reason: 'category' },
        { id: 'extra', version: '1.0.0', image_digest: null, categories: ['quality'], options: {}, feeds: [], timeout_s: 60, history: 'shallow', reason: 'included' },
      ],
      gaps: [],
      timeout_s: 1560,
      created_at: '2026-11-24T08:01:00Z',
    },
    coverage: {
      gaps: [{ kind: 'profile-category', category: 'lint', module: null, reason: 'no-module' }, { kind: 'profile-module', category: null, module: 'absent', reason: 'not-installed' }, { kind: 'lockfile-missing', path: 'package.json' }, { kind: 'output-truncated' }],
      source: { files: 42, bytes: 1000, skipped: [{ path: 'big.bin', reason: 'size' }] },
    },
    verdict_details: { verdict: 'failed', reasons: [{ code: 'secret' }] },
    requested_by_username: null,
    by_api_token: true,
    queue_position: null,
    modules: [
      { module_id: 'gitleaks', module_version: '8.30.1', image_digest: null, feeds: [], status: 'ok', error_class: null, attempts: 1, results_count: 3, duration_ms: 4200, has_log: true, started_at: null, finished_at: null },
      { module_id: 'trivy', module_version: '0.76.2', image_digest: null, feeds: [], status: 'oom', error_class: 'infra', attempts: 1, results_count: null, duration_ms: 800, has_log: false, started_at: null, finished_at: null },
    ],
    ...patch,
  }
}

describe('liste des analyses', () => {
  it('file en direct : ordre du worker, priorité relevée par l’attente, rafraîchie', async () => {
    setUser('viewer')
    let n = 0
    route('GET', '/api/scans', () => {
      n++
      return { items: [summary(), summary({ id: NEW_ID, number: 8, trigger: 'release', priority: 90, effective_priority: 90, status: 'running' })], total: 2 }
    })
    vi.useFakeTimers({ shouldAdvanceTime: true })
    await mountIn(ScansPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('Boutique #7')
    expect(text).toContain('10 → 14')
    expect(text).toContain('En file')
    expect(text).toContain('En cours')
    expect(text).toContain('Planifié')
    expect(text).toContain('2 analyse(s)')
    expect(callsTo('GET', '/api/scans')[0]!.query).toMatchObject({ status: 'active' })
    await vi.advanceTimersByTimeAsync(3100)
    await settle()
    expect(n).toBeGreaterThan(1)
  })

  it('historique filtrable', async () => {
    setUser('viewer')
    route('GET', '/api/scans', _e => ({ items: [summary({ status: 'done', verdict: 'passed' })], total: 1 }))
    await mountIn(ScansPage)
    await settle()
    const tab = Array.from(document.body.querySelectorAll('[role="tab"]')).find(b => b.textContent?.includes('Historique'))!
    tab.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }))
    await settle()
    expect(bodyText()).toContain('Accepté')
    const last = callsTo('GET', '/api/scans').at(-1)!
    expect(last.query).toMatchObject({ limit: '50', offset: '0' })
    expect(last.query.status).toBeUndefined()
  })

  it('erreur de chargement : message traduit', async () => {
    setUser('viewer')
    route('GET', '/api/scans', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(ScansPage)
    await settle()
    expect(toastAdd).toHaveBeenCalled()
  })
})

describe('détail d’une analyse', () => {
  it('plan avec raisons, modules, journal, couverture, verdict brut ; anglais', async () => {
    setUser('viewer')
    route('GET', `/api/scans/${ID}`, () => detail())
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    const text = bodyText()
    expect(text).toContain('Boutique #7')
    expect(text).toContain('Refusé')
    expect(text).toContain('retenu pour : secrets')
    expect(text).toContain('retenu pour : dépendances')
    expect(text).toContain('demandé par le profil')
    expect(text).toContain('Réussi')
    expect(text).toContain('Mémoire insuffisante')
    expect(text).toContain('4.2 s')
    expect(text).toContain('3 résultat(s)')
    expect(text).toContain('42 fichier(s) analysé(s), 1 ignoré(s).')
    expect(text).toContain('Catégorie lint non couverte : aucun module installé et actif.')
    expect(text).toContain('Module absent non utilisé : module non installé.')
    expect(text).toContain('Fichier de verrouillage absent : package.json')
    expect(text).toContain('Sortie tronquée')
    expect(text).toContain('jeton d’API (CI)')
    expect(text).toContain('"code": "secret"')
    // viewer : ni journal (réservé aux opérateurs, G20) ni action
    expect(document.body.querySelector(`a[href="/api/scans/${ID}/modules/gitleaks/log"]`)).toBeNull()
    expect(buttons('Rejouer à l’identique')).toHaveLength(0)
    await setLocale('en')
    await settle()
    expect(bodyText()).toContain('selected for: secrets')
  })

  it('rejouer à l’identique : modale, indicateur, navigation vers la nouvelle analyse', async () => {
    setUser('operator')
    route('GET', `/api/scans/${ID}`, () => detail())
    route('GET', `/api/scans/${NEW_ID}`, () => detail({ id: NEW_ID, number: 8, status: 'queued', verdict: null, queue_position: 2, trigger: 'replay', replay_of: ID }))
    route('POST', `/api/scans/${ID}/replay`, () => ({ scan_id: NEW_ID, number: 8, merged: false }))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    expect(document.body.querySelector(`a[href="/api/scans/${ID}/modules/gitleaks/log"]`)).not.toBeNull()
    await click(button('Rejouer à l’identique'))
    expect(bodyText()).toContain('même commit, mêmes modules')
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/scans/${ID}/replay`)).toHaveLength(1)
    expect(callsTo('POST', `/api/scans/${ID}/replay`)[0]!.csrf).toBe('csrf-test')
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Analyse mise en file.' }))
  })

  it('relancer fusionnée ; annuler une analyse en file ; erreur propre aux analyses', async () => {
    setUser('operator')
    let status = 'queued'
    route('GET', `/api/scans/${ID}`, () => detail({
      status, verdict: null, verdict_details: null, queue_position: 3, effective_priority: 14, priority: 10,
      error: { code: 'E_OOM', class: 'infra', message: 'out of memory', retry_at: '2026-11-24T09:00:00Z' }, attempt: 2,
    }))
    route('POST', `/api/scans/${ID}/cancel`, () => {
      status = 'cancelled'
      return { scan_id: ID, status: 'cancelled' }
    })
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    const text = bodyText()
    expect(text).toContain('Position dans la file : 3')
    expect(text).toContain('relevée par l’attente')
    expect(text).toContain('Erreur d’infrastructure (relancée automatiquement)')
    expect(text).toContain('Le verdict sera rendu à la fin de l’analyse.')
    expect(buttons('Relancer')).toHaveLength(0)
    await click(button('Annuler'))
    expect(bodyText()).toContain('L’analyse est retirée de la file.')
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/scans/${ID}/cancel`)).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Analyse annulée.' }))
    await settle()
    expect(bodyText()).toContain('Annulée')

    resetApi()
    clearBody()
    route('GET', `/api/scans/${ID}`, () => detail({ plan: null }))
    route('POST', `/api/scans/${ID}/retry`, () => apiFail(409, 'E_SCAN_PROJECT_ARCHIVED'))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    expect(buttons('Rejouer à l’identique')).toHaveLength(0)
    expect(bodyText()).toContain('Le plan sera établi')
    await click(button('Relancer'))
    await click(button('Confirmer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Ce projet est archivé.', color: 'error' }))
  })

  it('analyse introuvable', async () => {
    setUser('viewer')
    route('GET', `/api/scans/${ID}`, () => apiFail(404, 'E_SCAN_NOT_FOUND'))
    await mountIn(ScanPage, { route: `/scans/${ID}` })
    await settle()
    expect(bodyText()).toContain('Analyse introuvable.')
  })
})
