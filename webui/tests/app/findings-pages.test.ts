// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Chantier D : pages Résultats, Exceptions et Gravités. Textes des scanners
// affichés comme texte (jamais interprétés), tri réservé aux opérateurs,
// modales de la console, paquets malveillants mis en évidence (H4), relance
// des secrets à révoquer (F7), gravités modifiables par un administrateur (G5).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { apiFail, bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import FindingsPage from '~/pages/findings/index.vue'
import ExceptionsPage from '~/pages/findings/exceptions.vue'
import SeveritiesPage from '~/pages/system/severities.vue'

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
const F1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const F2 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const F3 = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'

const base = {
  project_id: P1, project_slug: 'demo', project_name: 'Démo', fingerprint: 'f'.repeat(64), category: 'sca', native_severity: 'critical',
  path: 'package-lock.json', start_line: 15, vuln_ids: [], package: null, malicious: false, secret_type: null, secret_state: null,
  status: 'new', status_until: null, is_new: true, first_seen_at: '2026-11-24T08:00:00Z', updated_at: '2026-11-24T08:00:00Z',
}
const ROWS = [
  { ...base, id: F1, tool: 'osv-scanner', rule_id: 'MAL-2025-1', severity: 'critical', title: 'Paquet piégé', malicious: true, vuln_ids: ['MAL-2025-1'], package: { ecosystem: 'npm', name: 'evil', version: '1.0.0', fixed: [] } },
  { ...base, id: F2, tool: 'gitleaks', rule_id: 'generic-api-key', category: 'secrets', severity: 'medium', title: '<img src=x onerror=alert(1)>', path: '.env', secret_type: 'generic-api-key', secret_state: 'to-revoke' },
  { ...base, id: F3, tool: 'trivy', rule_id: 'CVE-2021-44906', severity: 'high', title: 'minimist: prototype pollution', is_new: false, vuln_ids: ['CVE-2021-44906'], package: { ecosystem: 'npm', name: 'minimist', version: '1.2.5', fixed: ['1.2.6'] } },
]
const SUMMARY = {
  projects: [
    { project_id: P1, project_slug: 'demo', project_name: 'Démo', open: 3, critical: 1, high: 1, medium: 1, low: 0, info: 0, secrets_to_revoke: 1, malicious: 1 },
    { project_id: P2, project_slug: 'autre', project_name: 'Autre', open: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, secrets_to_revoke: 0, malicious: 0 },
  ],
}
const detailOf = (row: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  ...row, message: 'Message <b>brut</b>', end_line: 15, snippet: 'KEY=[secret masqué : generic, longueur 32]', cwe: ['CWE-1321'],
  status_reason: null, status_by: null, status_at: null, secret_state_by: null, secret_state_at: null, first_commit: 'a'.repeat(40),
  last_commit: 'b'.repeat(40), accepted_expired: false, revoke_pending_days: row.secret_state === 'to-revoke' ? 4 : null,
  scans: [{ id: P2, number: 7, ref: 'main', is_new: true, queued_at: '2026-11-24T08:00:00Z' }], ...extra,
})

function setInput(el: HTMLInputElement | HTMLTextAreaElement, value: string) {
  el.value = value
  el.dispatchEvent(new Event('input', { bubbles: true }))
}
const dialogField = (tag: 'input' | 'textarea', type?: string) =>
  Array.from(document.body.querySelectorAll<HTMLInputElement>(`[role="dialog"] ${tag}`)).filter(i => !type || i.type === type)

function listRoutes(details: Record<string, ReturnType<typeof detailOf>> = {}) {
  route('GET', '/api/findings', () => ({ items: ROWS, total: 3 }))
  route('GET', '/api/findings/summary', () => SUMMARY)
  for (const row of ROWS) route('GET', `/api/findings/${row.id}`, () => details[row.id] ?? detailOf(row))
}

describe('page Résultats', () => {
  it('liste, alertes H4 et F7, vue par projet, textes jamais interprétés', async () => {
    setUser('viewer')
    listRoutes()
    const w = await mountIn(FindingsPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('3 résultat(s)')
    expect(text).toContain('1 paquet(s) malveillant(s)')
    expect(text).toContain('1 secret(s) à révoquer')
    expect(text).toContain('Vue par projet')
    expect(text).toContain('<img src=x onerror=alert(1)>')
    expect(document.body.querySelector('img[src="x"]')).toBeNull()
    expect(text).toContain('malveillant')
    expect(text).toContain('evil@1.0.0')
    expect(text).toContain('.env:15')
    expect(callsTo('GET', '/api/findings')[0]!.query).toMatchObject({ limit: '50', offset: '0', status: 'new,confirmed' })
    expect(w.findAll('tbody tr')).toHaveLength(3)
  })

  it('filtres lus dans l\'adresse ; alerte « Afficher » ; filtre par projet', async () => {
    setUser('viewer')
    listRoutes()
    await mountIn(FindingsPage, { route: `/findings?project_id=${P1}&secret=true&severity=high&status=all&is_new=true&tool=trivy&q=min&category=sca&scan_id=${P2}` })
    await settle()
    expect(callsTo('GET', '/api/findings')[0]!.query).toMatchObject({ project_id: P1, secret: 'true', severity: 'high', is_new: 'true', tool: 'trivy', q: 'min', category: 'sca', scan_id: P2 })
    expect(callsTo('GET', '/api/findings')[0]!.query.status).toBeUndefined()
    expect(bodyText()).not.toContain('Vue par projet')
  })

  it('le filtre « Afficher » des paquets malveillants recharge la liste', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      setUser('viewer')
      listRoutes()
      await mountIn(FindingsPage)
      await settle()
      await click(buttons('Afficher')[0]!)
      await vi.advanceTimersByTimeAsync(400)
      await settle()
      const last = callsTo('GET', '/api/findings').at(-1)!
      expect(last.query).toMatchObject({ malicious: 'true' })
      expect(last.query.status).toBeUndefined()
      await click(button('Démo'))
      await vi.advanceTimersByTimeAsync(400)
      await settle()
      expect(callsTo('GET', '/api/findings').at(-1)!.query).toMatchObject({ project_id: P1 })
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('détail d\'un lecteur : extrait masqué, message en texte, aucune action', async () => {
    setUser('viewer')
    listRoutes()
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[1]!.trigger('click')
    await settle()
    const text = bodyText()
    expect(text).toContain('Détail du résultat')
    expect(text).toContain('[secret masqué : generic, longueur 32]')
    expect(text).toContain('Message <b>brut</b>')
    expect(document.body.querySelector('[data-testid="finding-detail"] b')).toBeNull()
    expect(text).toContain('À révoquer depuis 4 jour(s)')
    expect(text).toContain('Analyse n°7 · main')
    expect(text).toContain('CWE-1321')
    expect(buttons('Confirmer')).toHaveLength(0)
    expect(buttons('Marquer révoqué')).toHaveLength(0)
    expect(document.body.querySelector('[data-slot="finding-ai"]')).not.toBeNull()
  })

  it('paquet malveillant : ni faux positif ni acceptation proposés', async () => {
    setUser('operator')
    listRoutes()
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[0]!.trigger('click')
    await settle()
    expect(bodyText()).toContain('il bloque toujours la release')
    expect(buttons('Faux positif')).toHaveLength(0)
    expect(buttons('Accepter temporairement')).toHaveLength(0)
    expect(buttons('Créer une exception')).toHaveLength(0)
    expect(buttons('Confirmer').length).toBeGreaterThan(0)
  })

  it('acceptation : motif et date de fin requis, envoyés au serveur', async () => {
    setUser('operator')
    listRoutes()
    route('POST', `/api/findings/${F3}/status`, (_e, body) => detailOf(ROWS[2]!, { status: 'accepted', status_by: 'alice', status_at: '2026-11-24T09:00:00Z', status_until: (body as { until: string }).until, status_reason: (body as { reason: string }).reason }))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[2]!.trigger('click')
    await settle()
    expect(bodyText()).toContain('corrigé en 1.2.6')
    await click(button('Accepter temporairement'))
    expect(bodyText()).toContain('redevient nouveau de lui-même')
    expect(button('Confirmer').disabled).toBe(true)
    setInput(dialogField('textarea')[0]!, 'Montée de version planifiée')
    await settle()
    expect(button('Confirmer').disabled).toBe(false)
    const until = dialogField('input', 'date')[0]!
    setInput(until, '2000-01-01')
    await settle()
    expect(button('Confirmer').disabled).toBe(true)
    const soon = new Date(Date.now() + 10 * 86400_000).toISOString().slice(0, 10)
    setInput(until, soon)
    await settle()
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F3}/status`)[0]!.body).toEqual({ status: 'accepted', reason: 'Montée de version planifiée', until: soon })
    expect(callsTo('POST', `/api/findings/${F3}/status`)[0]!.csrf).toBe('csrf-test')
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Résultat mis à jour.' }))
    expect(bodyText()).toContain(`jusqu’au ${soon}`)
  })

  it('confirmer, rouvrir ; refus du serveur affiché (E_MALICIOUS)', async () => {
    setUser('operator')
    listRoutes()
    route('POST', `/api/findings/${F3}/status`, (_e, body) => ((body as { status: string }).status === 'confirmed'
      ? detailOf(ROWS[2]!, { status: 'confirmed', status_by: 'alice', status_at: '2026-11-24T09:00:00Z' })
      : apiFail(409, 'E_MALICIOUS')))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[2]!.trigger('click')
    await settle()
    await click(buttons('Confirmer').at(-1)!)
    expect(bodyText()).toContain('Confirmé par alice')
    await click(button('Rouvrir'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Refusé : un paquet malveillant ne peut être ni accepté ni exempté.', color: 'error' }))
  })

  it('faux positif avec motif', async () => {
    setUser('operator')
    listRoutes()
    route('POST', `/api/findings/${F3}/status`, () => detailOf(ROWS[2]!, { status: 'false-positive' }))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[2]!.trigger('click')
    await settle()
    await click(button('Faux positif'))
    expect(bodyText()).toContain('Classer en faux positif')
    setInput(dialogField('textarea')[0]!, 'Code de test')
    await settle()
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F3}/status`)[0]!.body).toEqual({ status: 'false-positive', reason: 'Code de test' })
  })

  it('secret (F7) : révocation confirmée par une modale, puis « pas un secret »', async () => {
    setUser('operator')
    listRoutes()
    route('POST', `/api/findings/${F2}/secret`, (_e, body) => detailOf(ROWS[1]!, { secret_state: (body as { state: string }).state, secret_state_by: 'alice', secret_state_at: '2026-11-24T09:00:00Z', revoke_pending_days: null }))
    const w = await mountIn(FindingsPage)
    await settle()
    await w.findAll('tbody tr')[1]!.trigger('click')
    await settle()
    await click(button('Marquer révoqué'))
    expect(bodyText()).toContain('Marquer le secret comme révoqué')
    await click(button('Confirmer'))
    expect(callsTo('POST', `/api/findings/${F2}/secret`)[0]!.body).toEqual({ state: 'revoked' })
    expect(bodyText()).toContain('Révoqué par alice')
    await click(button('Pas un secret'))
    expect(callsTo('POST', `/api/findings/${F2}/secret`)[1]!.body).toEqual({ state: 'false-positive' })
  })

  it('erreurs de chargement signalées', async () => {
    setUser('viewer')
    route('GET', '/api/findings', () => apiFail(500, 'E_INTERNAL'))
    route('GET', '/api/findings/summary', () => apiFail(500, 'E_INTERNAL'))
    await mountIn(FindingsPage)
    await settle()
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })

  it('en anglais', async () => {
    await setLocale('en')
    setUser('viewer')
    listRoutes()
    await mountIn(FindingsPage)
    await settle()
    expect(bodyText()).toContain('3 finding(s)')
    expect(bodyText()).toContain('1 malicious package(s)')
  })
})

const EXC = [
  { id: 'e1', project_id: P1, kind: 'path', target: { glob: 'tests/**' }, reason: 'Jeux de test', expires_on: '2027-01-01', created_by: 'alice', created_at: '2026-11-24T08:00:00Z', revoked_at: null, revoked_by: null, active: true, expired: false },
  { id: 'e2', project_id: P1, kind: 'vuln', target: { vuln_id: 'CVE-2021-44906' }, reason: 'Ancienne', expires_on: '2026-01-01', created_by: 'bob', created_at: '2025-11-24T08:00:00Z', revoked_at: null, revoked_by: null, active: false, expired: true },
]

describe('page Exceptions', () => {
  it('liste par projet, création pré-remplie depuis un résultat, révocation par modale', async () => {
    setUser('operator')
    route('GET', '/api/findings/summary', () => SUMMARY)
    route('GET', '/api/exceptions', () => ({ items: EXC }))
    route('POST', '/api/exceptions', () => ({ id: 'e3' }))
    route('DELETE', '/api/exceptions/e1', () => ({ ...EXC[0], active: false, revoked_at: '2026-11-24T09:00:00Z' }))
    await mountIn(ExceptionsPage, { route: `/findings/exceptions?project_id=${P1}&finding_id=${F3}` })
    await settle()
    expect(callsTo('GET', '/api/exceptions')[0]!.query).toEqual({ project_id: P1 })
    expect(bodyText()).toContain('glob=tests/**')
    expect(bodyText()).toContain('échue')
    // Création pré-remplie (type « résultat »).
    expect(bodyText()).toContain('Demander une exception')
    expect((document.body.querySelector<HTMLInputElement>('[role="dialog"] input')!).value).toBe(F3)
    expect(button('Envoyer la demande').disabled).toBe(true)
    setInput(dialogField('textarea')[0]!, 'Faux positif accepté par l’équipe')
    await settle()
    await click(button('Envoyer la demande'))
    const body = callsTo('POST', '/api/exceptions')[0]!.body as Record<string, unknown>
    expect(body).toMatchObject({ project_id: P1, kind: 'finding', target: { finding_id: F3 }, reason: 'Faux positif accepté par l’équipe' })
    expect(String(body.expires_on)).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Demande envoyée : un administrateur doit l’approuver.' }))

    await click(buttons('Révoquer')[0]!)
    expect(bodyText()).toContain('Révoquer l’exception')
    await click(buttons('Confirmer').at(-1)!)
    expect(callsTo('DELETE', '/api/exceptions/e1')).toHaveLength(1)
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Exception révoquée.' }))
  })

  it('lecteur : aucune création ni révocation ; erreur de création signalée', async () => {
    setUser('viewer')
    route('GET', '/api/findings/summary', () => ({ projects: [SUMMARY.projects[0]] }))
    route('GET', '/api/exceptions', () => ({ items: [EXC[0]] }))
    await mountIn(ExceptionsPage)
    await settle()
    expect(callsTo('GET', '/api/exceptions')[0]!.query).toEqual({ project_id: P1 })
    expect(buttons('Demander une exception')).toHaveLength(0)
    expect(buttons('Révoquer')).toHaveLength(0)
  })

  it('opérateur : création d\'une exception de chemin, refus du serveur', async () => {
    setUser('operator')
    route('GET', '/api/findings/summary', () => ({ projects: [SUMMARY.projects[0]] }))
    route('GET', '/api/exceptions', () => ({ items: [] }))
    route('POST', '/api/exceptions', () => apiFail(409, 'E_MALICIOUS'))
    await mountIn(ExceptionsPage)
    await settle()
    expect(bodyText()).toContain('Aucune exception.')
    await click(button('Demander une exception'))
    const inputs = Array.from(document.body.querySelectorAll<HTMLInputElement>('[role="dialog"] input[type="text"], [role="dialog"] input:not([type])'))
    setInput(inputs[0]!, 'tests/**')
    setInput(dialogField('textarea')[0]!, 'Jeux de test')
    await settle()
    await click(button('Envoyer la demande'))
    expect(callsTo('POST', '/api/exceptions')[0]!.body).toMatchObject({ kind: 'path', target: { glob: 'tests/**' } })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ color: 'error' }))
  })
})

const MAPS = [
  { module_id: 'trivy', native: 'critical', severity: 'critical', origin: 'critical', builtin: true, updated_by: null, updated_at: '2026-11-24T08:00:00Z' },
  { module_id: 'trivy', native: 'low', severity: 'medium', origin: 'low', builtin: false, updated_by: 'admin', updated_at: '2026-11-24T08:00:00Z' },
]

describe('page Gravités (G5)', () => {
  it('administrateur : valeur d\'origine affichée, retour à l\'origine', async () => {
    setUser('admin')
    route('GET', '/api/severity-maps', () => ({ items: MAPS }))
    route('PATCH', '/api/severity-maps', () => ({ module_id: 'trivy', native: 'low', severity: 'low', builtin: true }))
    await mountIn(SeveritiesPage)
    await settle()
    const text = bodyText()
    expect(text).toContain('trivy')
    expect(text).toContain('modifiée par admin')
    expect(document.body.querySelector('[data-testid="map-trivy:low"]')).not.toBeNull()
    await click(button('Revenir à l’origine'))
    expect(callsTo('PATCH', '/api/severity-maps')[0]!.body).toEqual({ module_id: 'trivy', native: 'low', severity: null })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Gravité enregistrée. Elle s’applique dès la prochaine analyse.' }))
  })

  it('lecteur : lecture seule ; table vide', async () => {
    setUser('viewer')
    route('GET', '/api/severity-maps', () => ({ items: [] }))
    await mountIn(SeveritiesPage)
    await settle()
    expect(bodyText()).toContain('Seul un administrateur peut modifier cette table.')
    expect(bodyText()).toContain('Aucune gravité native rencontrée')
  })

  it('erreur d\'enregistrement signalée', async () => {
    setUser('admin')
    route('GET', '/api/severity-maps', () => ({ items: MAPS }))
    route('PATCH', '/api/severity-maps', () => apiFail(404, 'E_NOT_FOUND'))
    await mountIn(SeveritiesPage)
    await settle()
    await click(button('Revenir à l’origine'))
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Élément introuvable.', color: 'error' }))
  })
})
