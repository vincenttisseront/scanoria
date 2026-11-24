// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.5, chantier C : Résultats avec EPSS et KEV (H3) et recoupement entre outils
// (F16). Colonne EPSS (pourcentage et percentile), badge KEV, filtres EPSS et
// KEV, regroupement actif par défaut, « confirmé par N outils », détail avec
// liens vers chaque résultat d'origine, tri appliqué à tout le groupe.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import FindingsPage from '~/pages/findings/index.vue'
import IntelBadges from '~/components/findings/IntelBadges.vue'

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
const F1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const F2 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const F3 = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const GROUP = {
  key: 'a'.repeat(64), project_id: P1, confirmations: 2, tools: ['osv-scanner', 'trivy'],
  members: [{ id: F1, tool: 'trivy', severity: 'high', status: 'new' }, { id: F2, tool: 'osv-scanner', severity: 'medium', status: 'new' }],
}
const base = {
  project_id: P1, project_slug: 'demo', project_name: 'Démo', fingerprint: 'f'.repeat(64), category: 'sca', native_severity: 'high',
  path: 'package-lock.json', start_line: null, malicious: false, secret_type: null, secret_state: null,
  status: 'new', status_until: null, is_new: true, first_seen_at: '2026-11-24T08:00:00Z', updated_at: '2026-11-24T08:00:00Z',
  epss: null, epss_percentile: null, kev: false, kev_added: null, correlation_key: null, group: null,
}
const ROWS = [
  { ...base, id: F1, tool: 'trivy', rule_id: 'CVE-2026-0001', severity: 'high', title: 'kev-lib : exécution de code', vuln_ids: ['CVE-2026-0001'],
    package: { ecosystem: 'npm', name: 'kev-lib', version: '1.0.0', fixed: [] }, kev: true, kev_added: '2026-11-20', epss: 0.4213, epss_percentile: 0.973, correlation_key: GROUP.key, group: GROUP },
  { ...base, id: F3, tool: 'trivy', rule_id: 'CVE-2026-0003', severity: 'medium', title: 'calm-lib', vuln_ids: ['CVE-2026-0003'],
    package: { ecosystem: 'npm', name: 'calm-lib', version: '1.0.0', fixed: [] }, epss: 0.0004, epss_percentile: 0.05 },
]
const detailOf = (row: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  ...row, message: null, end_line: null, snippet: null, cwe: [], status_reason: null, status_by: null, status_at: null,
  secret_state_by: null, secret_state_at: null, first_commit: null, last_commit: null, accepted_expired: false,
  revoke_pending_days: null, scans: [], ...extra,
})

function routes() {
  route('GET', '/api/findings', () => ({ items: ROWS, total: 2 }))
  route('GET', '/api/findings/summary', () => ({ projects: [] }))
  route('GET', '/api/intel/status', () => ({ feeds: [
    { id: 'epss', rows: 3, imported_at: '2026-11-24T07:00:00Z', source_updated_at: '2026-11-24T06:00:00Z' },
    { id: 'kev', rows: 1, imported_at: '2026-11-24T07:00:00Z', source_updated_at: '2026-11-24T05:00:00Z' },
  ] }))
  route('GET', `/api/findings/${F1}`, () => detailOf(ROWS[0]!))
  route('GET', `/api/findings/${F2}`, () => detailOf({ ...ROWS[0]!, id: F2, tool: 'osv-scanner', severity: 'medium', title: 'GHSA kev-lib' }))
  route('GET', `/api/findings/${F3}`, () => detailOf(ROWS[1]!))
}

describe('Résultats : EPSS, KEV et recoupement', () => {
  it('colonne EPSS, badge KEV, « confirmé par 2 outils », regroupement demandé par défaut', async () => {
    setUser('viewer')
    routes()
    await mountIn(FindingsPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('KEV')
    expect(text).toContain('42,1 % · percentile 97,3 %')
    expect(text).toContain('0,04 % · percentile 5 %')
    expect(text).toContain('Confirmé par 2 outils')
    expect(document.body.querySelectorAll('[data-testid="kev-badge"]')).toHaveLength(1)
    expect(document.body.querySelector('[data-testid="correlation-badge"]')!.getAttribute('title')).toContain('osv-scanner, trivy')
    expect(callsTo('GET', '/api/findings')[0]!.query).toMatchObject({ grouped: 'true' })
    expect(callsTo('GET', '/api/findings')[0]!.query.kev).toBeUndefined()
    expect(document.body.querySelector('[data-testid="intel-status"]')).not.toBeNull()
    expect(document.body.querySelector('[data-testid="epss-attribution"]')!.textContent).toBe('EPSS, FIRST.org')
  })

  it('filtres EPSS et KEV lus dans l’adresse ; regroupement désactivable', async () => {
    setUser('viewer')
    routes()
    await mountIn(FindingsPage, { route: '/findings?epss_min=0.1&kev=true&grouped=false' })
    await settle()
    const q = callsTo('GET', '/api/findings')[0]!.query
    expect(q).toMatchObject({ epss_min: '0.1', kev: 'true' })
    expect(q.grouped).toBeUndefined()
  })

  it('seuil EPSS inconnu dans l’adresse ignoré ; bases absentes signalées', async () => {
    setUser('viewer')
    route('GET', '/api/findings', () => ({ items: [], total: 0 }))
    route('GET', '/api/findings/summary', () => ({ projects: [] }))
    route('GET', '/api/intel/status', () => ({ feeds: [{ id: 'epss', rows: null, imported_at: null, source_updated_at: null }, { id: 'kev', rows: null, imported_at: null, source_updated_at: null }] }))
    await mountIn(FindingsPage, { route: '/findings?epss_min=0.3' })
    await settle()
    expect(callsTo('GET', '/api/findings')[0]!.query.epss_min).toBeUndefined()
    expect(bodyText()).toContain('installer les bases « EPSS » et « CISA KEV »')
  })

  it('détail : exploitation, groupe et lien vers l’autre résultat', async () => {
    setUser('viewer')
    routes()
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[0]!.trigger('click')
    await settle()
    const text = bodyText()
    expect(text).toContain('Exploitation')
    expect(text).toContain('Oui, ajoutée le 2026-11-20')
    expect(document.body.querySelector('[data-testid="epss-attribution-detail"]')!.textContent).toBe('EPSS, FIRST.org')
    expect(text).toContain('Recoupement entre outils')
    expect(text).toContain('osv-scanner')
    await click(document.body.querySelector(`[data-testid="correlation-open-${F2}"]`)!)
    await settle()
    expect(callsTo('GET', `/api/findings/${F2}`)).toHaveLength(1)
    expect(bodyText()).toContain('GHSA kev-lib')
  })

  it('tri d’un groupe : envoyé à group-status, détail relu ; case décochée : un seul résultat', async () => {
    setUser('operator')
    routes()
    route('POST', `/api/findings/${F1}/group-status`, () => ({ updated: [F1, F2] }))
    route('POST', `/api/findings/${F1}/status`, () => detailOf(ROWS[0]!, { status: 'new' }))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[0]!.trigger('click')
    await settle()
    expect(bodyText()).toContain('Appliquer le tri aux 2 résultats du groupe')
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F1}/group-status`)[0]!.body).toEqual({ status: 'confirmed' })
    expect(callsTo('GET', `/api/findings/${F1}`).length).toBe(2)
    const box = document.body.querySelector<HTMLElement>('[data-testid="correlation-group"] [role="checkbox"]')!
    await click(box)
    await settle()
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F1}/status`)).toHaveLength(1)
  })

  it('résultat sans groupe : tri classique, aucune case', async () => {
    setUser('operator')
    routes()
    route('POST', `/api/findings/${F3}/status`, () => detailOf(ROWS[1]!, { status: 'confirmed' }))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[1]!.trigger('click')
    await settle()
    expect(document.body.querySelector('[data-testid="correlation-group"]')).toBeNull()
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F3}/status`)).toHaveLength(1)
  })
})

describe('IntelBadges', () => {
  it('rien de connu : tiret ; anglais : séparateur décimal anglais', async () => {
    const none = await mountIn(IntelBadges, { props: { epss: null, epssPercentile: null, kev: false } })
    expect(none.text()).toBe('—')
    await setLocale('en')
    const en = await mountIn(IntelBadges, { props: { epss: 0.5, epssPercentile: null, kev: true, kevAdded: null } })
    expect(en.text()).toContain('50 % · percentile —')
    expect(en.find('[data-testid="kev-badge"]').attributes('title')).toBe('Known exploited vulnerability: CISA KEV catalog.')
  })
})
