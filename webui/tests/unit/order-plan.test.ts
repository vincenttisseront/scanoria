// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.6 (V3, V5, chantier D) : ordre du plan par durée mesurée et graphe SBOM.

import { describe, expect, it } from 'vitest'
import { DEFAULT_EXPECTED_MS, expectedMs, orderModules, sbomRole, type Durations } from '../../server/scans/order'
import { catalogEntry, parsePlan, scanPlanSchema, type PlanCatalogEntry, type PlannedModule } from '../../server/scans/plan'

const DIGEST = `sha256:${'d'.repeat(64)}`

function entry(id: string, scan: Record<string, unknown>, outputs: Record<string, unknown> = { sarif: {} }): PlanCatalogEntry {
  return catalogEntry({ id, version: '1.0.0', type: 'scanner', categories: ['sca'], image: `x@${DIGEST}`, outputs, scan: { inputs: ['repo'], command: ['x'], ...scan } })!
}
function planned(e: PlanCatalogEntry): PlannedModule {
  return { id: e.id, version: e.version, image: e.image, image_digest: DIGEST, categories: e.categories, options: {}, feeds: [], timeout_s: 60, history: 'shallow', outputs: e.outputs, reason: 'category' }
}
const durations = (project: Record<string, number> = {}, appliance: Record<string, number> = {}): Durations =>
  ({ project: new Map(Object.entries(project)), appliance: new Map(Object.entries(appliance)) })

const syft = entry('syft', {}, { cyclonedx: {} })
const grype = entry('grype', { inputs: ['repo', 'sbom'], prefers_sbom: true, sbom_command: ['y'] })
const dtrack = entry('dtrack-upload', { inputs: ['repo', 'sbom'], requires_sbom: true })
const osv = entry('osv-scanner', { inputs: ['repo', 'sbom'], sbom_command: ['y'] })
const gitleaks = entry('gitleaks', {})
const catalog = new Map([syft, grype, dtrack, osv, gitleaks].map(e => [`${e.id}@${e.version}`, e]))
const all = [gitleaks, grype, osv, syft, dtrack].map(planned)

describe('order (V3, V5)', () => {
  it('rôles SBOM : producteur, consommateurs (prefers ou requires), sbom_command seul ne suffit pas', () => {
    expect(all.map(m => [m.id, sbomRole(m, catalog)])).toEqual([
      ['gitleaks', null], ['grype', 'consumer'], ['osv-scanner', null], ['syft', 'producer'], ['dtrack-upload', 'consumer'],
    ])
  })

  it('durée : projet, puis appliance, puis défaut', () => {
    const d = durations({ a: 10 }, { a: 99, b: 20 })
    expect([expectedMs('a', d), expectedMs('b', d), expectedMs('c', d)]).toEqual([10, 20, DEFAULT_EXPECTED_MS])
    expect(expectedMs('z', durations({ z: 0 }))).toBe(1)
  })

  it('les longs d’abord, la chaîne SBOM comptée en entier, le graphe toujours respecté', () => {
    const out = orderModules(all, catalog, durations({ 'gitleaks': 50_000, 'syft': 20_000, 'grype': 40_000, 'dtrack-upload': 5_000, 'osv-scanner': 55_000 }))
    // syft : 20 s + grype 40 s = 60 s > osv 55 s > gitleaks 50 s ; grype puis dtrack après syft.
    expect(out.map(m => m.id)).toEqual(['syft', 'osv-scanner', 'gitleaks', 'grype', 'dtrack-upload'])
    expect(out.find(m => m.id === 'grype')!.after).toEqual(['syft'])
    expect(out.find(m => m.id === 'dtrack-upload')!.after).toEqual(['syft'])
    expect(out.find(m => m.id === 'osv-scanner')!.after).toEqual([])
    expect(out.map(m => m.expected_ms)).toEqual([20_000, 55_000, 50_000, 40_000, 5_000])
    for (const [i, m] of out.entries()) for (const d of m.after!) expect(out.findIndex(x => x.id === d)).toBeLessThan(i)
  })

  it('même entrée, même ordre (égalités départagées par l’identifiant) ; sans producteur, aucun graphe', () => {
    const noSyft = all.filter(m => m.id !== 'syft')
    const a = orderModules(noSyft, catalog, durations())
    const b = orderModules([...noSyft].reverse(), catalog, durations())
    expect(a).toEqual(b)
    expect(a.map(m => m.id)).toEqual(['dtrack-upload', 'gitleaks', 'grype', 'osv-scanner'])
    expect(a.every(m => m.after!.length === 0)).toBe(true)
  })

  it('plan : champs 0.6 facultatifs, plan antérieur relu tel quel (G11)', () => {
    const base = {
      version: 1, created_at: '2026-11-24T10:00:00Z', source: { kind: 'git', ref: 'main', commit: null, history: 'shallow' },
      profile: { id: 'p', slug: 'complet', categories: [], include_modules: [], exclude_modules: [] },
      gate: { id: 'g', slug: 'defaut', rules: {} }, gaps: [], timeout_s: 60,
    }
    const old = parsePlan({ ...base, modules: [planned(gitleaks)] })
    expect(old!.modules[0]!.after).toBeUndefined()
    const now = parsePlan({ ...base, modules: orderModules([planned(syft), planned(grype)], catalog, durations()) })
    expect(now!.modules.map(m => [m.id, m.after])).toEqual([['syft', []], ['grype', ['syft']]])
    expect(scanPlanSchema.safeParse({ ...base, modules: [{ ...planned(gitleaks), after: ['Bad id'] }] }).success).toBe(false)
  })
})
