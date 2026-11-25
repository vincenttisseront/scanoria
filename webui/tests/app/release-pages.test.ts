// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// 0.8 (A) : page Release (§ 7) : verdict, statut scanoria/release-gate,
// signature, téléchargements, publications, comparaison F2 (précédente puis
// release choisie, liens vers les résultats), écart entre verdict signé et
// verdict actuel, rapport en erreur, notes I6 proposées par IA, erreurs.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { apiFail, bodyText, callsTo, clearBody, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ReleasePage from '~/pages/releases/[scanId].vue'

enableAutoUnmount(afterEach)

beforeEach(async () => {
  await setLocale('fr')
})
afterEach(() => {
  resetApi()
  clearBody()
})

const P1 = '11111111-1111-4111-8111-111111111111'
const S1 = '33333333-3333-4333-8333-333333333333'
const S0 = '55555555-5555-4555-8555-555555555555'
const S9 = '66666666-6666-4666-8666-666666666666'
const F1 = '44444444-4444-4444-8444-444444444444'
const COMMIT = 'a'.repeat(40)

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
function bucket(total: number, items: { id: string, severity: string, title: string, tool?: string, path?: string | null }[] = []) {
  return {
    total,
    by_severity: { ...zero, high: total },
    by_tool: {},
    items: items.map(i => ({ tool: 'osv-scanner', rule_id: 'GHSA-1', path: 'package-lock.json', ...i })),
  }
}

function view(patch: Record<string, unknown> = {}) {
  return {
    scan_id: S1,
    project_id: P1,
    project_slug: 'demo',
    project_name: 'Démo',
    tag: 'v1.2.0',
    commit_sha: COMMIT,
    source: 'pull',
    scan_number: 7,
    scan_status: 'done',
    verdict: 'passed',
    signed_verdict: 'passed',
    report_status: 'signed',
    report_sha256: 'b'.repeat(64),
    key_fingerprint: 'c'.repeat(64),
    signed_at: '2026-11-25T10:00:00Z',
    error: null,
    previous_scan_id: S0,
    comparison: { from_scan_id: S0, to_scan_id: S1, introduced: bucket(1, [{ id: F1, severity: 'high', title: 'Composant vulnérable' }]), fixed: bucket(0), unchanged: bucket(2) },
    gate_context: 'scanoria/release-gate',
    gate: { state: 'success', description: 'v1.2.0 : favorable' },
    publications: {
      'gate.published': { outcome: 'success', details: { state: 'success' }, at: '2026-11-25T10:01:00Z' },
      'assets': { outcome: 'success', details: { outcome: 'missing-permission' }, at: '2026-11-25T10:01:00Z' },
    },
    files: { 'report.json': true, 'results.sarif': true, 'sbom.cdx.json': false },
    ...patch,
  }
}

function releases() {
  route('GET', '/api/releases', () => ({
    items: [
      { scan_id: S1, tag: 'v1.2.0', report_status: 'signed' },
      { scan_id: S0, tag: 'v1.1.0', report_status: 'signed' },
      { scan_id: S9, tag: 'v1.0.0', report_status: 'error' },
    ],
  }))
}

function aiNotes(output: Record<string, unknown> | null) {
  route('GET', '/api/ai/output', () => (output
    ? { enabled: true, opt_out: false, task: { id: 't-notes', status: 'done', locale: 'fr', error: null, model: 'qwen-test:14b', model_digest: 'd'.repeat(64), generated_at: '2026-11-25T10:02:00Z', output, feedback: null } }
    : { enabled: false, opt_out: false, task: null }))
}

describe('page Release', () => {
  it('release signée : verdict, gate, signature, fichiers, publications, comparaison et notes IA', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => view())
    releases()
    aiNotes({ headline: 'Une dépendance vulnérable introduite.', fixed: 'Rien de corrigé.', introduced: 'GHSA-1 sur un composant.', accepted: 'Aucune exception.' })
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    const text = bodyText()
    expect(text).toContain('Release v1.2.0')
    expect(w.find('[data-testid="release-gate"]').text()).toBe('Gate : favorable')
    expect(w.find('[data-testid="release-signature"]').text()).toBe('Rapport signé')
    expect(w.find('[data-testid="release-waiting"]').exists()).toBe(false)
    expect(w.find('[data-testid="release-verdict-changed"]').exists()).toBe(false)
    expect(text).toContain(COMMIT)
    expect(text).toContain('c'.repeat(64))
    expect(text).toContain('Démo #7')
    // Fichiers : le SBOM absent est désactivé ; le rapport pointe vers la route signée.
    const report = w.find('[data-testid="release-file-report"]')
    expect(report.attributes('href')).toBe(`/api/releases/${S1}/report.json`)
    const sbom = w.find('[data-testid="release-file-sbom"]')
    expect(sbom.attributes('aria-disabled') === 'true' || sbom.attributes('disabled') !== undefined).toBe(true)
    const pubs = w.find('[data-testid="release-publications"]').text()
    expect(pubs).toContain('Statut de commit : publié')
    expect(pubs).toContain('droit manquant sur la forge')
    expect(pubs).toContain('Notes de sécurité jointes : pas encore')
    // Comparaison F2 avec la précédente : lien vers les résultats filtrés.
    const cmp = w.find('[data-testid="release-compare"]')
    expect(cmp.text()).toContain('Composant vulnérable')
    const link = cmp.findAll('a').map(a => a.attributes('href')).find(h => h?.startsWith('/findings'))
    expect(link).toBe(`/findings?project_id=${P1}&tool=osv-scanner&q=GHSA-1&status=all`)
    // La liste de comparaison ne propose que les autres releases signées.
    expect(callsTo('GET', '/api/releases')[0]!.query).toEqual({ project: P1 })
    // Notes I6 : annexe non signée.
    expect(w.find('[data-testid="release-notes"]').text()).toContain('Une dépendance vulnérable introduite.')
    expect(w.find('[data-testid="release-notes"]').text()).toContain('Annexe non signée')
  })

  it('verdict changé par une exception depuis la signature : écart affiché', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => view({ verdict: 'passed', signed_verdict: 'failed', comparison: null, previous_scan_id: null }))
    releases()
    aiNotes(null)
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    expect(w.find('[data-testid="release-verdict-changed"]').exists()).toBe(true)
    expect(w.find('[data-testid="release-compare"]').text()).toContain('Aucune release précédente signée')
  })

  it('rapport en erreur : bloquant, aucun téléchargement du rapport ni notes', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => view({
      report_status: 'error',
      error: 'E_SIGN_TIMEOUT',
      key_fingerprint: null,
      gate: { state: 'failure', description: 'v1.2.0 : rapport non signé : bloquant' },
      files: { 'report.json': false, 'results.sarif': true, 'sbom.cdx.json': true },
      comparison: null,
      publications: {},
    }))
    releases()
    aiNotes(null)
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    expect(w.find('[data-testid="release-signature"]').text()).toBe('Rapport non signé')
    expect(w.find('[data-testid="release-gate"]').text()).toBe('Gate : bloquée')
    expect(bodyText()).toContain('la release reste bloquée')
    expect(bodyText()).toContain('E_SIGN_TIMEOUT')
    expect(w.find('[data-testid="release-notes"]').exists()).toBe(false)
    expect(callsTo('GET', '/api/ai/output')).toHaveLength(0)
  })

  it('analyse en cours : indicateur d\'attente, rien de signé', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => view({
      scan_status: 'running', verdict: null, signed_verdict: null, report_status: null, key_fingerprint: null,
      gate: { state: 'pending', description: 'v1.2.0 : analyse de release en cours' }, comparison: null, publications: {}, files: {},
    }))
    releases()
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    expect(w.find('[data-testid="release-waiting"]').exists()).toBe(true)
    expect(w.find('[data-testid="release-gate"]').text()).toBe('Gate : en attente')
    expect(w.find('[data-testid="release-signature"]').text()).toBe('Rapport en préparation')
  })

  it('analyse qui n\'est pas une release : message d\'erreur traduit', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => apiFail(404, 'E_RELEASE_NOT_FOUND'))
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    expect(w.find('[data-testid="release-error"]').text()).toContain('Cette analyse n’est pas une release.')
  })

  it('erreur inconnue : message générique', async () => {
    setUser('viewer')
    route('GET', `/api/releases/${S1}`, () => apiFail(500, 'E_INTERNAL'))
    const w = await mountIn(ReleasePage, { route: `/releases/${S1}` })
    await settle()
    expect(w.find('[data-testid="release-error"]').text()).toContain('Release illisible.')
  })
})
