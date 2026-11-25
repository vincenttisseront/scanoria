// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Pages des jeux de règles (G4, 0.7 chantier A) : liste, règles maison en
// lecture seule (vue, copie pour modifier), création et import (rappel des
// conditions Semgrep, case obligatoire), fiche : nouvelle version, validation
// par le moteur avec indicateur d'attente, écart, retour arrière et archivage
// par des modales de la console, rattachement aux profils ; lecteur en
// lecture seule ; anglais.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { mockNuxtImport } from '@nuxt/test-utils/runtime'
import { bodyText, button, buttons, callsTo, clearBody, click, mountIn, resetApi, route, setLocale, settle, setUser } from './helpers'
import ListPage from '~/pages/rulesets/index.vue'
import DetailPage from '~/pages/rulesets/[id].vue'

const { toastAdd, navigateToMock } = vi.hoisted(() => ({ toastAdd: vi.fn(), navigateToMock: vi.fn() }))
mockNuxtImport('useToast', () => () => ({ add: toastAdd }))
mockNuxtImport('navigateTo', () => navigateToMock)

enableAutoUnmount(afterEach)

const RS = '11111111-1111-4111-8111-111111111111'
const PROFILE = '22222222-2222-4222-8222-222222222222'
const OTHER = '33333333-3333-4333-8333-333333333333'
const RULES = 'rules:\n  - id: interne-eval\n    pattern: eval(...)\n'

async function mount(...args: Parameters<typeof mountIn>) {
  const w = await mountIn(...args)
  await settle()
  return w
}
function typeIn(testid: string, value: string) {
  const el = document.body.querySelector<HTMLInputElement | HTMLTextAreaElement>(`[data-testid="${testid}"] input, [data-testid="${testid}"] textarea, input[data-testid="${testid}"], textarea[data-testid="${testid}"]`)!
  el.value = value
  el.dispatchEvent(new Event('input'))
}
const byTestId = (id: string) => document.body.querySelector<HTMLElement>(`[data-testid="${id}"]`)!

beforeEach(async () => {
  await setLocale('fr')
  toastAdd.mockReset()
  navigateToMock.mockReset()
})
afterEach(() => {
  vi.useRealTimers()
  resetApi()
  clearBody()
})

const row = (patch: Record<string, unknown> = {}) => ({
  id: RS, slug: 'interne', engine: 'opengrep', name: 'Règles internes', description: null, created_at: '2026-11-25T08:00:00Z',
  archived_at: null, latest_version: 2, latest_sha256: 'a'.repeat(64), latest_origin: 'manual', latest_at: '2026-11-25T09:00:00Z', profiles: 1, ...patch,
})
const builtin = { slug: 'scanoria-base', engine: 'opengrep', license: 'AGPL-3.0-or-later', sha256: 'b'.repeat(64), content: RULES, rules: 20 }

describe('liste des jeux de règles', () => {
  it('affiche les jeux, les règles maison (vue en modale) et crée un jeu', async () => {
    setUser('admin')
    route('GET', '/api/rulesets', () => ({ items: [row()] }))
    route('GET', '/api/rulesets/builtin', () => ({ items: [builtin] }))
    route('POST', '/api/rulesets', () => ({ id: RS, version: 1, sha256: 'c'.repeat(64) }))
    await mount(ListPage)
    const text = bodyText()
    expect(text).toContain('Règles internes')
    expect(text).toContain('Version 2')
    expect(text).toContain('1 profil(s)')
    expect(text).toContain('20 règles')
    await click(button('Voir'))
    expect(document.body.querySelector('pre code')?.textContent).toContain('interne-eval')
    clearBody()
    await mount(ListPage)
    await click(byTestId('ruleset-new'))
    const confirm = () => byTestId('ruleset-create-confirm') as HTMLButtonElement
    expect(confirm().disabled).toBe(true)
    typeIn('ruleset-slug', 'interne-2')
    typeIn('ruleset-name', 'Équipe')
    typeIn('ruleset-content', RULES)
    await settle()
    expect(confirm().disabled).toBe(false)
    await click(confirm())
    expect(callsTo('POST', '/api/rulesets')[0]!.body).toMatchObject({ slug: 'interne-2', engine: 'opengrep', name: 'Équipe', content: RULES, origin: 'manual' })
    expect(navigateToMock).toHaveBeenCalledWith(`/rulesets/${RS}`)
  })

  it('copie des règles maison : formulaire prérempli', async () => {
    setUser('admin')
    route('GET', '/api/rulesets', () => ({ items: [] }))
    route('GET', '/api/rulesets/builtin', () => ({ items: [builtin] }))
    await mount(ListPage)
    expect(bodyText()).toContain('Aucun jeu de règles')
    await click(byTestId('ruleset-builtin-copy'))
    expect((document.body.querySelector('[data-testid="ruleset-slug"] input, input[data-testid="ruleset-slug"]') as HTMLInputElement).value).toBe('scanoria-base-copie')
    expect((document.body.querySelector('[data-testid="ruleset-content"] textarea, textarea[data-testid="ruleset-content"]') as HTMLTextAreaElement).value).toBe(RULES)
  })

  it('import Opengrep : champ fichier, sans rappel des conditions Semgrep', async () => {
    setUser('admin')
    route('GET', '/api/rulesets', () => ({ items: [] }))
    route('GET', '/api/rulesets/builtin', () => ({ items: [] }))
    route('POST', '/api/rulesets', () => ({ id: RS, version: 1, sha256: 'c'.repeat(64) }))
    await mount(ListPage)
    await click(byTestId('ruleset-import'))
    expect(byTestId('ruleset-file')).not.toBeNull()
    typeIn('ruleset-slug', 'semgrep-officiel')
    typeIn('ruleset-name', 'Semgrep')
    typeIn('ruleset-content', RULES)
    await settle()
    expect(byTestId('semgrep-license-ack')).toBeNull()
    await click(byTestId('ruleset-create-confirm'))
    expect(callsTo('POST', '/api/rulesets')[0]!.body).toMatchObject({ origin: 'import', engine: 'opengrep' })
    expect(callsTo('POST', '/api/rulesets')[0]!.body).not.toHaveProperty('license_ack')
  })

  it('lecteur : lecture seule, aucun bouton de création', async () => {
    setUser('viewer')
    route('GET', '/api/rulesets', () => ({ items: [row({ archived_at: '2026-11-25T10:00:00Z' })] }))
    route('GET', '/api/rulesets/builtin', () => ({ items: [builtin] }))
    await mount(ListPage)
    expect(bodyText()).toContain('Lecture seule')
    expect(bodyText()).toContain('Archivé')
    expect(byTestId('ruleset-new')).toBeNull()
    expect(byTestId('ruleset-builtin-copy')).toBeNull()
  })
})

describe('fiche d’un jeu de règles', () => {
  const versions = [
    { version: 2, sha256: 'a'.repeat(64), comment: 'exec', origin: 'manual', created_by: 1, created_by_name: 'alice', created_at: '2026-11-25T09:00:00Z', bytes: 120 },
    { version: 1, sha256: 'd'.repeat(64), comment: null, origin: 'import', created_by: 1, created_by_name: 'alice', created_at: '2026-11-25T08:00:00Z', bytes: 60 },
  ]
  function detail(patch: Record<string, unknown> = {}, attachments: unknown[] = [{ profile_id: PROFILE, profile_slug: 'complet', pinned_version: null }]) {
    route('GET', `/api/rulesets/${RS}`, () => ({
      ruleset: row(patch), versions, attachments,
      profiles: [{ id: PROFILE, slug: 'complet', builtin: true }, { id: OTHER, slug: 'rapide', builtin: true }],
    }))
    route('GET', `/api/rulesets/${RS}/versions/2`, () => ({ version: 2, content: RULES, sha256: 'a'.repeat(64),
      diff_from: 1, diff: [{ op: ' ', text: 'rules:' }, { op: '+', text: '  - id: interne-exec' }] }))
    route('GET', `/api/rulesets/${RS}/versions/1`, () => ({ version: 1, content: 'rules: []\n', sha256: 'd'.repeat(64) }))
  }

  it('nouvelle version enregistrée, historique, écart et retour arrière par une modale', async () => {
    setUser('admin')
    detail()
    route('POST', `/api/rulesets/${RS}/versions`, () => ({ version: 3, sha256: 'e'.repeat(64) }))
    route('POST', `/api/rulesets/${RS}/rollback`, () => ({ version: 4, sha256: 'd'.repeat(64) }))
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    expect(bodyText()).toContain('Règles internes')
    expect(bodyText()).toContain('par alice')
    expect((document.body.querySelector('[data-testid="ruleset-editor"] textarea, textarea[data-testid="ruleset-editor"]') as HTMLTextAreaElement).value).toBe(RULES)
    typeIn('ruleset-editor', `${RULES}# v3\n`)
    await settle()
    await click(byTestId('ruleset-save'))
    expect(callsTo('POST', `/api/rulesets/${RS}/versions`)[0]!.body).toMatchObject({ content: `${RULES}# v3\n` })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Version 3 enregistrée.' }))
    await click(buttons('Écart avec la précédente')[0]!)
    expect(byTestId('ruleset-diff').textContent).toContain('+   - id: interne-exec')
    clearBody()
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    await click(byTestId('ruleset-rollback-1'))
    expect(bodyText()).toContain('Revenir à la version 1')
    await click(byTestId('ruleset-rollback-confirm'))
    expect(callsTo('POST', `/api/rulesets/${RS}/rollback`)[0]!.body).toEqual({ version: 1 })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Version 4 créée.' }))
  })

  it('validation par le moteur : demande suivie avec indicateur d’attente, résultats par exemple', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    setUser('admin')
    detail()
    route('POST', '/api/rulesets/validate', () => ({ request_id: 'r1' }))
    route('GET', '/api/requests/r1', () => ({ id: 'r1', type: 'validate-ruleset', status: 'ok', code: 'OK', step: null, message: null,
      output: { engine: 'opengrep', module: 'opengrep', version: '2.0.0', ok: true, errors: [], samples: [{ name: 'app.py', matches: 1 }] } }))
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    await click(button('Ajouter un exemple'))
    const name = document.body.querySelector<HTMLInputElement>('input[placeholder="app.py"]')!
    name.value = 'app.py'
    name.dispatchEvent(new Event('input'))
    await settle()
    await click(byTestId('ruleset-validate'))
    expect(document.body.querySelector('[role="status"]')).not.toBeNull()
    for (let i = 0; i < 3; i++) await vi.advanceTimersByTimeAsync(2100)
    await settle()
    expect(callsTo('POST', '/api/rulesets/validate')[0]!.body).toMatchObject({ engine: 'opengrep', content: RULES, ruleset_id: RS, samples: [{ name: 'app.py', content: '' }] })
    expect(byTestId('ruleset-validation').textContent).toContain('Règles acceptées par opengrep 2.0.0')
    expect(byTestId('ruleset-validation').textContent).toContain('1 résultat(s)')
  })

  it('profils : retrait puis enregistrement ; archivage refusé tant que rattaché, puis confirmé', async () => {
    setUser('admin')
    detail()
    route('PUT', `/api/rulesets/${RS}/profiles`, () => ({ attachments: [] }))
    route('PATCH', `/api/rulesets/${RS}`, () => ({ ruleset: row({ archived_at: '2026-11-25T10:00:00Z' }) }))
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    expect(bodyText()).toContain('complet')
    await click(byTestId('ruleset-archive'))
    expect(bodyText()).toContain('Détachez d’abord ce jeu')
    expect((byTestId('ruleset-archive-confirm') as HTMLButtonElement).disabled).toBe(true)
    clearBody()
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    await click(button('Retirer'))
    await click(byTestId('ruleset-profiles-save'))
    expect(callsTo('PUT', `/api/rulesets/${RS}/profiles`)[0]!.body).toEqual({ profiles: [] })
    resetApi()
    detail({}, [])
    route('PATCH', `/api/rulesets/${RS}`, () => ({ ruleset: row({ archived_at: '2026-11-25T10:00:00Z' }) }))
    clearBody()
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    await click(byTestId('ruleset-archive'))
    await click(byTestId('ruleset-archive-confirm'))
    expect(callsTo('PATCH', `/api/rulesets/${RS}`)[0]!.body).toEqual({ archived: true })
    expect(toastAdd).toHaveBeenCalledWith(expect.objectContaining({ title: 'Jeu de règles archivé.' }))
  })

  it('jeu archivé : désarchivage direct ; lecteur : aucune action ; anglais', async () => {
    setUser('admin')
    detail({ archived_at: '2026-11-25T10:00:00Z' }, [])
    route('PATCH', `/api/rulesets/${RS}`, () => ({ ruleset: row() }))
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    expect(byTestId('ruleset-save')).toBeNull()
    await click(byTestId('ruleset-archive'))
    expect(callsTo('PATCH', `/api/rulesets/${RS}`)[0]!.body).toEqual({ archived: false })
    clearBody()
    resetApi()
    setUser('viewer')
    await setLocale('en')
    detail()
    await mount(DetailPage, { route: `/rulesets/${RS}` })
    expect(bodyText()).toContain('History')
    expect(bodyText()).toContain('Latest version')
    expect(byTestId('ruleset-validate')).toBeNull()
    expect(byTestId('ruleset-archive')).toBeNull()
    expect(byTestId('ruleset-rollback-1')).toBeNull()
  })
})
