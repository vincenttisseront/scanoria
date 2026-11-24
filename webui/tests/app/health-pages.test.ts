// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Page « Santé des analyses » (G20) : santé par outil sur 7 puis 30 jours,
// analyses en échec récentes avec lien, journal téléchargeable réservé aux
// opérateurs, indicateur d'attente et rafraîchissement sans recharger, anglais.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, button, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import HealthPage from '~/pages/scans/health.vue'
import type { ScanHealth, ToolHealth } from '~/composables/useUsage'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const SCAN = '3f1c2a9e-7b4d-4e2a-9c1f-0a1b2c3d4e5f'

function tool(patch: Partial<ToolHealth> = {}): ToolHealth {
  return {
    module_id: 'trivy', runs: 10, ok: 7, failures: 3, failure_rate: 0.3, by_class: { infra: 1, tool: 1, input: 1 },
    timeouts: 1, oom: 1, invalid_output: 0, duration_avg_ms: 2500, duration_p95_ms: 9000, last_failure_at: '2026-11-24T08:00:00Z', ...patch,
  }
}

function health(): ScanHealth {
  return {
    windows: { 7: [tool()], 30: [tool({ module_id: 'gitleaks', runs: 40, failures: 0, failure_rate: 0, by_class: { infra: 0, tool: 0, input: 0 }, last_failure_at: null })] },
    recent_failures: [{
      id: SCAN, number: 12, project_id: 'p1', project_name: 'Boutique', status: 'error', finished_at: '2026-11-24T08:00:00Z',
      modules: [{ module_id: 'trivy', status: 'oom', error_class: 'infra', has_log: true }, { module_id: 'gitleaks', status: 'timeout', error_class: 'tool', has_log: false }],
    }],
    generated_at: '2026-11-24T09:00:00Z',
  }
}

describe('santé des analyses', () => {
  it('par outil sur 7 jours puis 30 ; analyses en échec avec lien ; journal pour un opérateur', async () => {
    setUser('operator')
    let n = 0
    route('GET', '/api/health/scans', () => {
      n++
      return health()
    })
    await mountIn(HealthPage, { route: '/scans/health' })
    await settle()
    let text = bodyText()
    expect(text).toContain('Santé des analyses')
    expect(text).toContain('trivy')
    expect(text).toContain('30 %')
    expect(text).toContain('9 s')
    expect(text).toContain('Boutique #12')
    expect(text).toContain('Mémoire insuffisante')
    expect(document.body.querySelector(`a[href="/scans/${SCAN}"]`)).not.toBeNull()
    expect(document.body.querySelector(`a[href="/api/scans/${SCAN}/modules/trivy/log"]`)).not.toBeNull()
    // pas de journal copié pour gitleaks : pas de lien
    expect(document.body.querySelector(`a[href="/api/scans/${SCAN}/modules/gitleaks/log"]`)).toBeNull()
    expect(text).not.toContain('40')
    const tab = Array.from(document.body.querySelectorAll('button')).find(b => b.textContent?.trim() === '30 jours')!
    tab.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }))
    await settle()
    text = bodyText()
    // fenêtre de 30 jours : gitleaks, 40 exécutions, aucun échec
    expect(text).toContain('40')
    expect(text).not.toContain('30 %')
    await click(button('Actualiser'))
    expect(n).toBe(2)
  })

  it('lecteur : statistiques visibles, journal non proposé', async () => {
    setUser('viewer')
    route('GET', '/api/health/scans', () => health())
    await mountIn(HealthPage, { route: '/scans/health' })
    await settle()
    expect(bodyText()).toContain('Boutique #12')
    expect(document.body.querySelector(`a[href="/api/scans/${SCAN}/modules/trivy/log"]`)).toBeNull()
  })

  it('vide, erreur, anglais', async () => {
    setUser('viewer')
    route('GET', '/api/health/scans', () => ({ windows: { 7: [], 30: [] }, recent_failures: [], generated_at: '2026-11-24T09:00:00Z' }))
    await mountIn(HealthPage, { route: '/scans/health' })
    await settle()
    expect(bodyText()).toContain('Aucune analyse sur cette période.')
    expect(bodyText()).toContain('Aucune analyse en échec sur 30 jours.')
    resetApi()
    clearBody()
    await setLocale('en')
    route('GET', '/api/health/scans', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(HealthPage, { route: '/scans/health' })
    await settle()
    expect(bodyText()).toContain('Scan health')
    expect(bodyText()).toContain('Recent failed scans (30 days)')
  })
})
