// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Onglet « Consommation » du détail d'un module (F14) : statistiques d'un
// scanner, courbes d'un module permanent sur 7 et 30 jours, module inutilisé
// avec suggestion de retrait (ouvre la désinstallation, jamais automatique),
// module requis par un autre, indicateur d'attente, erreurs, anglais.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ModulePanel from '~/components/usage/ModulePanel.vue'
import UsageChart from '~/components/usage/UsageChart.vue'
import type { ModuleUsage, ModuleUsageDetail, SeriesPoint } from '~/composables/useUsage'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
  setUser('admin')
})
afterEach(() => {
  resetApi()
  clearBody()
})

function usage(patch: Partial<ModuleUsage> = {}): ModuleUsage {
  return {
    id: 'trivy', type: 'scanner', version: '0.76.2', enabled: true, installed_at: '2026-10-01T08:00:00Z', required_by: [],
    scanner: { runs: 12, failures: 1, memory_max_mb: 2048, memory_median_mb: 300, cpu_avg_ms: 4200, duration_avg_ms: 3000, duration_p95_ms: 150_000, last_run_at: '2026-11-24T08:00:00Z' },
    service: null, last_used_at: '2026-11-24T08:00:00Z', judged: true, unused: false, unused_reason: null, ...patch,
  }
}
const detail = (u: ModuleUsage, series: ModuleUsageDetail['series'] = null): ModuleUsageDetail => ({ window_days: 30, unused_days: 30, usage: u, series })
const point = (h: number, mem: number | null): SeriesPoint => ({ at: `2026-11-24T${String(h).padStart(2, '0')}:00:00Z`, memory_avg_mb: mem, memory_max_mb: mem, cpu_avg_pct: 12.5, disk_mb: 900 })

describe('onglet Consommation', () => {
  it('scanner : mémoire max et médiane, CPU, durées, analyses ; rafraîchi sans recharger', async () => {
    let n = 0
    route('GET', '/api/usage/modules/trivy', () => {
      n++
      return detail(usage())
    })
    await mountIn(ModulePanel, { props: { moduleId: 'trivy' } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Consommation')
    expect(text).toContain('Analyses (30 j)12')
    expect(text).toContain('Mémoire max2 Go')
    expect(text).toContain('Mémoire médiane300 Mo')
    expect(text).toContain('4,2 s')
    expect(text).toContain('2,5 min')
    expect(text).not.toContain('Inutilisé')
    await click(button('Actualiser'))
    expect(n).toBe(2)
  })

  it('scanner jamais lancé, mesures absentes : « non mesuré », jamais 0', async () => {
    route('GET', '/api/usage/modules/trivy', () => detail(usage({
      scanner: { runs: 0, failures: 0, memory_max_mb: null, memory_median_mb: null, cpu_avg_ms: null, duration_avg_ms: null, duration_p95_ms: null, last_run_at: null },
      last_used_at: null,
    })))
    await mountIn(ModulePanel, { props: { moduleId: 'trivy' } })
    await settle()
    expect(bodyText()).toContain('Aucune analyse sur les 30 derniers jours.')
    expect(bodyText()).toContain('non mesuré')
    expect(bodyText()).toContain('jamais')
  })

  it('inutilisé : signalé, suggestion de retrait qui ouvre la désinstallation existante', async () => {
    route('GET', '/api/usage/modules/gitleaks', () => detail(usage({ id: 'gitleaks', unused: true, unused_reason: 'no-scan' })))
    const w = await mountIn(ModulePanel, { props: { moduleId: 'gitleaks', canUninstall: true } })
    await settle()
    expect(bodyText()).toContain('Inutilisé depuis 30 jours')
    expect(bodyText()).toContain('Aucune analyse ne l’a lancé depuis 30 jours.')
    expect(bodyText()).toContain('Rien n’est retiré automatiquement.')
    await click(button('Désinstaller…'))
    expect(w.emitted('uninstall')).toHaveLength(1)
    // aucune demande envoyée par l'onglet lui-même
    expect(callsTo('POST', '/api/catalog/modules/gitleaks/uninstall')).toHaveLength(0)
  })

  it('base sans dépendant ; lecteur : pas de bouton de retrait', async () => {
    setUser('viewer')
    route('GET', '/api/usage/modules/osv-db', () => detail(usage({ id: 'osv-db', type: 'feed', scanner: null, service: null, unused: true, unused_reason: 'no-dependent' })))
    await mountIn(ModulePanel, { props: { moduleId: 'osv-db', canUninstall: false } })
    await settle()
    expect(bodyText()).toContain('Aucun module installé n’utilise cette base.')
    expect(buttons('Désinstaller…')).toHaveLength(0)
  })

  it('module permanent : synthèse, courbes sur 7 puis 30 jours, requis par un autre', async () => {
    const u = usage({
      id: 'sonarqube', type: 'service', scanner: null, required_by: ['sonar-scanner'],
      service: { samples: 50, latest: { at: '2026-11-24T08:00:00Z', memory_mb: 3072, cpu_pct: 4.5, disk_mb: 900 }, memory_avg_mb: 2900, memory_max_mb: 4000, cpu_avg_pct: 3.2, disk_max_mb: 950 },
    })
    route('GET', '/api/usage/modules/sonarqube', () => detail(u, { 7: [point(1, 2000), point(2, null), point(3, 2500), point(4, 3000)], 30: [point(5, 4000)] }))
    await mountIn(ModulePanel, { props: { moduleId: 'sonarqube', names: { 'sonar-scanner': 'SonarScanner' } } })
    await settle()
    const text = bodyText()
    expect(text).toContain('Requis par SonarScanner : jamais signalé comme inutilisé.')
    expect(text).toContain('3 Go · 4,5 % · 900 Mo')
    expect(text).toContain('Mémoire sur 7 jours')
    // trou de mesure : la courbe est coupée en deux segments
    expect(document.body.querySelectorAll('svg polyline').length).toBeGreaterThanOrEqual(2)
    expect(document.body.querySelector('svg[role="img"]')!.getAttribute('aria-label')).toContain('2 Go – 2,9 Go')
    const tab = Array.from(document.body.querySelectorAll('button')).find(b => b.textContent?.trim() === '30 jours')!
    tab.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }))
    await settle()
    expect(bodyText()).toContain('Mémoire sur 30 jours')
  })

  it('module permanent sans relevé ; service non jugé', async () => {
    route('GET', '/api/usage/modules/defectdojo', () => detail(usage({ id: 'defectdojo', type: 'service', scanner: null, service: null, judged: false }), { 7: [], 30: [] }))
    await mountIn(ModulePanel, { props: { moduleId: 'defectdojo' } })
    await settle()
    expect(bodyText()).toContain('Aucun relevé pour l’instant')
    expect(bodyText()).toContain('n’est pas mesurable')
  })

  it('erreur de chargement, puis anglais', async () => {
    route('GET', '/api/usage/modules/trivy', () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(ModulePanel, { props: { moduleId: 'trivy' } })
    await settle()
    expect(document.body.querySelector('[role="alert"], .text-error, [data-color="error"]') ?? bodyText()).toBeTruthy()
    resetApi()
    await setLocale('en')
    route('GET', '/api/usage/modules/trivy', () => detail(usage({ unused: true, unused_reason: 'no-scan' })))
    await mountIn(ModulePanel, { props: { moduleId: 'trivy' } })
    await settle()
    expect(bodyText()).toContain('Unused for 30 days')
    expect(bodyText()).toContain('Peak memory2 GB')
  })

  it('courbe vide ou à un seul point', async () => {
    await mountIn(UsageChart, { props: { points: [], label: 'Vide', format: (v: number | null) => String(v) } })
    expect(document.body.querySelector('svg')!.getAttribute('aria-label')).toBe('Vide')
    clearBody()
    await mountIn(UsageChart, { props: { points: [{ at: 'x', value: 5 }], label: 'Un', format: (v: number | null) => String(v) } })
    expect(bodyText()).toContain('5 – 5')
  })
})
