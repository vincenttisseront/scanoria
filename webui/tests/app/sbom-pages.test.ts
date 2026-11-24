// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.5 (B) : page Composants (F3 : recherche, page suivante avec les critères
// de la dernière recherche, export CSV, erreur), page Licences (F8 : défauts,
// ajout et retrait par un administrateur dans une modale de la console, essai
// d'une expression, lecture seule), bandeau des projets touchés, décision de
// licence d'un composant.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { getQuery } from 'h3'
import { apiFail, bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ComponentsPage from '~/pages/components/index.vue'
import LicensesPage from '~/pages/system/licenses.vue'
import ExposureBanner from '~/components/sbom/ExposureBanner.vue'
import LicenseDecision from '~/components/sbom/LicenseDecision.vue'

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
const P2 = '22222222-2222-4222-8222-222222222222'
const S1 = '33333333-3333-4333-8333-333333333333'
const F1 = '44444444-4444-4444-8444-444444444444'

function hit(id: string, slug: string, archived = false) {
  return {
    project: { id, slug, name: `Projet ${slug}`, archived },
    scan: { id: S1, number: 3, ref: 'main', finished_at: '2026-11-24T08:00:00Z' },
    components: [{
      purl: 'pkg:npm/minimist@1.2.5', ecosystem: 'npm', name: 'minimist', version: '1.2.5', licenses: ['MIT'], direct: true,
      published_at: null,
      findings: [{ id: F1, tool: 'osv-scanner', severity: 'critical', status: 'new', vuln_ids: ['GHSA-xvch-5gv4-984h'], title: 't' }],
    }],
  }
}

function typeIn(selector: string, value: string) {
  const input = document.body.querySelector<HTMLInputElement>(selector)!
  input.value = value
  input.dispatchEvent(new Event('input'))
}

describe('page Composants', () => {
  it('recherche depuis l’adresse, résultats par projet, page suivante, export CSV', async () => {
    setUser('viewer')
    route('GET', '/api/components', (event) => {
      const q = getQuery(event)
      return q.cursor
        ? { items: [hit(P2, 'beta', true)], next_cursor: null, total_projects: 2, total_components: 2, truncated: false }
        : { items: [hit(P1, 'alpha')], next_cursor: 'c1', total_projects: 2, total_components: 2, truncated: true }
    })
    await mountIn(ComponentsPage, { route: '/components?q=minimist&from=1.0.0' })
    await settle()
    expect(callsTo('GET', '/api/components')[0]!.query).toEqual({ name: 'minimist', version_from: '1.0.0' })
    expect(bodyText()).toContain('Projet alpha')
    expect(bodyText()).toContain('2 projet(s), 2 composant(s).')
    expect(bodyText()).toContain('Recherche tronquée')
    expect(bodyText()).toContain('GHSA-xvch-5gv4-984h')
    expect(bodyText()).toContain('date inconnue')

    // Formulaire modifié sans relancer : « Projets suivants » et le CSV gardent la dernière recherche.
    typeIn('[data-testid="components-query"] input, input[data-testid="components-query"]', 'lodash')
    await settle()
    const csv = document.body.querySelector<HTMLAnchorElement>('[data-testid="components-csv"]')!
    expect(csv.getAttribute('href')).toBe('/api/components/export.csv?name=minimist&version_from=1.0.0')
    await click(document.body.querySelector('[data-testid="components-more"]')!)
    expect(callsTo('GET', '/api/components')[1]!.query).toEqual({ name: 'minimist', version_from: '1.0.0', cursor: 'c1' })
    expect(bodyText()).toContain('Projet beta')
    expect(bodyText()).toContain('archivé')
    expect(document.body.querySelector('[data-testid="components-more"]')).toBeNull()
  })

  it('purl et avis ; aucun résultat ; erreur affichée', async () => {
    setUser('viewer')
    let fail = false
    route('GET', '/api/components', () => (fail
      ? apiFail(500, 'E_INTERNAL')
      : { items: [], next_cursor: null, total_projects: 0, total_components: 0, truncated: false }))
    await mountIn(ComponentsPage, { route: '/components' })
    await settle()
    expect(bodyText()).toContain('Indiquez un nom, un purl ou un avis.')
    expect(callsTo('GET', '/api/components')).toHaveLength(0)
    typeIn('[data-testid="components-query"] input, input[data-testid="components-query"]', 'pkg:npm/minimist@1.2.5')
    typeIn('[data-testid="components-vuln"] input, input[data-testid="components-vuln"]', 'cve-2021-44906')
    await settle()
    await click(document.body.querySelector('[data-testid="components-search"]')!)
    expect(callsTo('GET', '/api/components')[0]!.query).toEqual({ purl: 'pkg:npm/minimist@1.2.5', vuln: 'CVE-2021-44906' })
    expect(bodyText()).toContain('Aucun projet n’utilise ce composant.')
    expect(document.body.querySelector('[data-testid="components-csv"]')).toBeNull()
    fail = true
    await click(document.body.querySelector('[data-testid="components-search"]')!)
    expect(bodyText()).toContain('Erreur interne de la console.')
  })
})

describe('page Licences', () => {
  const policy = (rows: unknown[] = []) => ({
    defaults: { version: 1, allowed: ['MIT', 'Apache-2.0'], otherwise: 'review', unknown: 'review' },
    global: rows, project: null, projects_with_overrides: [],
  })
  const row = { id: '55555555-5555-4555-8555-555555555555', project_id: null, license: 'GPL-3.0-only', decision: 'denied', reason: 'copyleft fort', updated_by_username: 'alice', updated_at: '2026-11-24T08:00:00Z' }

  it('administrateur : défauts, ajout global, retrait confirmé dans une modale, essai d’une expression', async () => {
    setUser('admin')
    let rows: unknown[] = []
    route('GET', '/api/licenses/policy', () => policy(rows))
    route('GET', '/api/projects', () => ({ items: [{ id: P1, name: 'Projet alpha' }] }))
    route('PUT', '/api/licenses/policy', () => {
      rows = [row]
      return row
    })
    route('DELETE', `/api/licenses/policy/${row.id}`, () => {
      rows = []
      return row
    })
    route('POST', '/api/licenses/evaluate', () => ({ decision: 'denied', source: 'global' }))
    await mountIn(LicensesPage, { route: '/system/licenses' })
    await settle()
    expect(document.body.querySelector('[data-testid="licenses-defaults"]')!.textContent).toContain('Apache-2.0')
    expect(bodyText()).toContain('Aucune décision : les défauts s’appliquent.')

    typeIn('input[placeholder="GPL-3.0-only"]', ' GPL-3.0-only ')
    typeIn('input[placeholder="Motif"]', 'copyleft fort')
    await settle()
    await click(button('Ajouter'))
    expect(callsTo('PUT', '/api/licenses/policy')[0]!.body).toEqual({ license: 'GPL-3.0-only', decision: 'review', reason: 'copyleft fort', project_id: null })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Décision enregistrée.' }))
    expect(document.body.querySelector('[data-testid="policy-GPL-3.0-only"]')!.textContent).toContain('Interdite')

    await click(button('Retirer'))
    expect(bodyText()).toContain('Retirer cette décision ?')
    await click(button('Confirmer'))
    expect(callsTo('DELETE', `/api/licenses/policy/${row.id}`)).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Décision retirée.' }))

    typeIn('input[aria-label="Expression SPDX"]', 'MIT AND GPL-3.0-only')
    await settle()
    await click(button('Évaluer'))
    expect(callsTo('POST', '/api/licenses/evaluate')[0]!.body).toEqual({ expression: 'MIT AND GPL-3.0-only', project_id: null })
    expect(document.body.querySelector('[data-testid="licenses-trial-result"]')!.textContent).toContain('Interdite · décision globale')
  })

  it('lecteur : lecture seule ; erreurs signalées', async () => {
    setUser('viewer')
    route('GET', '/api/licenses/policy', () => policy([row]))
    route('GET', '/api/projects', () => apiFail(500, 'E_INTERNAL'))
    route('POST', '/api/licenses/evaluate', () => apiFail(400, 'E_VALIDATION'))
    await mountIn(LicensesPage, { route: '/system/licenses' })
    await settle()
    expect(bodyText()).toContain('Lecture seule')
    expect(document.body.querySelector('[data-testid="licenses-form"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="policy-GPL-3.0-only"] button')).toBeNull()
    typeIn('input[aria-label="Expression SPDX"]', 'MIT AND (')
    await settle()
    await click(button('Évaluer'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })

  it('chargement en erreur : message', async () => {
    setUser('viewer')
    route('GET', '/api/licenses/policy', () => apiFail(500, 'E_INTERNAL'))
    route('GET', '/api/projects', () => ({ items: [] }))
    await mountIn(LicensesPage, { route: '/system/licenses' })
    await settle()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Erreur interne de la console.', color: 'error' }))
  })
})

describe('composants SBOM', () => {
  it('bandeau : projets nouvellement touchés, paquets malveillants en tête ; rien sinon', async () => {
    setUser('viewer')
    route('GET', '/api/components/exposures', () => ({
      items: [{ project: { id: P1, slug: 'alpha', name: 'Projet alpha' }, at: '2026-11-24T08:00:00Z', scan_id: S1, count: 2, malicious: 1, kev: 1, critical: 1, high: 0 }],
    }))
    await mountIn(ExposureBanner)
    await settle()
    const banner = document.body.querySelector('[data-testid="exposure-banner"]')!
    expect(banner.textContent).toContain('Nouveaux projets touchés après la mise à jour des bases (1)')
    expect(banner.textContent).toContain('1 paquet(s) malveillant(s)')
    expect(banner.textContent).toContain('1 exploitée(s) (KEV)')
    expect(banner.querySelector('a')!.getAttribute('href')).toBe(`/scans/${S1}`)
  })

  it('bandeau absent sans exposition ni en cas d’erreur', async () => {
    setUser('viewer')
    route('GET', '/api/components/exposures', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(ExposureBanner)
    await settle()
    expect(document.body.querySelector('[data-testid="exposure-banner"]')).toBeNull()
  })

  it('décision de licence d’un composant, en français et en anglais', async () => {
    const w = await mountIn(LicenseDecision, { props: { licenses: ['MIT', 'GPL-3.0-only'], decision: 'denied', source: 'project' } })
    expect(w.text()).toContain('MIT, GPL-3.0-only')
    expect(w.find('[data-testid="license-denied"]').attributes('title')).toBe('décision du projet')
    await setLocale('en')
    await w.setProps({ licenses: [], decision: 'review', source: undefined })
    expect(w.text()).toContain('no license')
    expect(w.text()).toContain('To review')
  })
})
